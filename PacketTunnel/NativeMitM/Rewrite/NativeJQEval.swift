// Native jq (fix/nc-jq-full) — evaluation, builtins and the public entry points. See NativeJQ.swift for the
// value model, JSON and the parser.
//
// Evaluation is a generator driven by callbacks: eval(node, input, path?, env, emit). With a non-nil path the node is
// evaluated as a path expression (path(f), |=, del, paths, …) and every output carries its path. Function parameters
// are closures (node + defining env), `$`-parameters bind both the variable and a constant filter, jq-defined builtins
// (Prelude) are mutually visible from a root scope, native builtins come last. Every run has a time budget and a
// recursion cap and runs on a thread with a large stack; an exhausted budget is an error (body passthrough).

import Foundation

typealias JQPath = [JQValue]
typealias JQEmit = (JQValue, JQPath?) throws -> Void

final class JQEnv {
    enum Entry {
        case root
        case variable(String, JQValue)
        case function(JQFuncDef)
        case closure(String, JQNode, JQEnv)
        case label(String, Int)
    }

    let parent: JQEnv?
    let entry: Entry

    init(_ parent: JQEnv?, _ entry: Entry) {
        self.parent = parent
        self.entry = entry
    }
}

// MARK: - Interpreter

final class JQInterp {
    private let deadline: UInt64
    private var steps = 0
    private var depth = 0
    private var ids = 0
    /// Call-depth cap (secondary; the stack guard below is what keeps unoptimized builds from overflowing).
    static let maxDepth = 20000
    /// Stack guard: the address of a local at construction (on the evaluating thread) and how far below it calls may go.
    private let stackBase: UInt
    private let stackBudget: UInt

    init(budget: TimeInterval) {
        deadline = DispatchTime.now().uptimeNanoseconds &+ UInt64(max(budget, 0.001) * 1e9)
        var marker: UInt8 = 0
        stackBase = withUnsafeMutablePointer(to: &marker) { UInt(bitPattern: $0) }
        var size = Thread.current.stackSize
        if size <= 0 { size = 512 << 10 }
        stackBudget = UInt(min(size, NativeJQ.stackSize)) / 10 * 7
    }

    @inline(never) private func stackUsed() -> UInt {
        var marker: UInt8 = 0
        let here = withUnsafeMutablePointer(to: &marker) { UInt(bitPattern: $0) }
        return stackBase > here ? stackBase - here : 0
    }

    func newID() -> Int { ids += 1; return ids }

    @inline(__always) func tick() throws {
        steps &+= 1
        if steps & 0x3FF == 0 && DispatchTime.now().uptimeNanoseconds > deadline {
            throw JQAbort(reason: "time budget exceeded")
        }
    }

    func invalidPath(_ x: JQValue) -> JQError { JQError("Invalid path expression with result \(JQOut.trunc(x))") }

    @inline(__always) func emitValue(_ x: JQValue, _ p: JQPath?, _ out: JQEmit) throws {
        if p != nil { throw invalidPath(x) }
        try out(x, nil)
    }

    static func locValue(_ line: Int) -> JQValue {
        var o = JQObject()
        o.set("file", .string("<top-level>"))
        o.set("line", .num(line))
        return .object(o)
    }

    func evalOpt(_ n: JQNode?, _ v: JQValue, _ env: JQEnv, _ k: (JQValue) throws -> Void) throws {
        guard let n else { try k(.null); return }
        try eval(n, v, nil, env) { x, _ in try k(x) }
    }

    /// `@_optimize(none)`: with -O the closure specializer clones this recursive generator once per closure literal
    /// passed to it (and again inside each clone) — swift-frontend went past 4.5 GB on this one function. Everything
    /// it calls stays optimized; the dispatch itself is cheap.
    @_optimize(none)
    func eval(_ n: JQNode, _ v: JQValue, _ p: JQPath?, _ env: JQEnv, _ out: JQEmit) throws {
        try tick()
        switch n {
        case .identity:
            try out(v, p)
        case .recurseAll:
            try recurseAll(v, p, out)
        case .literal(let x):
            try emitValue(x, p, out)
        case .loc(let line):
            try emitValue(Self.locValue(line), p, out)
        case .index(let t, let k):
            try eval(t, v, p, env) { tv, tp in
                try self.eval(k, v, nil, env) { kv, _ in
                    let r = try JQOps.index(tv, kv)
                    try out(r, tp.map { $0 + [kv] })
                }
            }
        case .slice(let t, let f, let to):
            try eval(t, v, p, env) { tv, tp in
                try self.evalOpt(f, v, env) { fv in
                    try self.evalOpt(to, v, env) { tov in
                        var o = JQObject()
                        o.set("start", fv)
                        o.set("end", tov)
                        let key = JQValue.object(o)
                        let r = try JQOps.index(tv, key)
                        try out(r, tp.map { $0 + [key] })
                    }
                }
            }
        case .iterate(let t):
            try eval(t, v, p, env) { tv, tp in
                switch tv {
                case .array(let a):
                    for (i, e) in a.enumerated() { try out(e, tp.map { $0 + [.num(i)] }) }
                case .object(let o):
                    for k in o.keys { try out(o.dict[k]!, tp.map { $0 + [.string(k)] }) }
                default:
                    throw JQError("Cannot iterate over \(JQOut.typed(tv))")
                }
            }
        case .optional(let b):
            try tryEval(b, nil, v, p, env, out)
        case .tryCatch(let b, let h):
            try tryEval(b, h, v, p, env, out)
        case .pipe(let a, let b):
            try eval(a, v, p, env) { av, ap in try self.eval(b, av, ap, env, out) }
        case .comma(let a, let b):
            try eval(a, v, p, env, out)
            try eval(b, v, p, env, out)
        case .neg(let e):
            try eval(e, v, nil, env) { x, _ in
                guard case .number(let d, _) = x else { throw JQError("\(JQOut.typed(x)) cannot be negated") }
                try self.emitValue(.num(-d), p, out)
            }
        case .binop(let op, let l, let r):
            try eval(r, v, nil, env) { rv, _ in
                try self.eval(l, v, nil, env) { lv, _ in
                    try self.emitValue(try JQOps.binop(op, lv, rv), p, out)
                }
            }
        case .and(let l, let r):
            try eval(l, v, nil, env) { lv, _ in
                if !lv.truthy { try self.emitValue(.bool(false), p, out); return }
                try self.eval(r, v, nil, env) { rv, _ in try self.emitValue(.bool(rv.truthy), p, out) }
            }
        case .or(let l, let r):
            try eval(l, v, nil, env) { lv, _ in
                if lv.truthy { try self.emitValue(.bool(true), p, out); return }
                try self.eval(r, v, nil, env) { rv, _ in try self.emitValue(.bool(rv.truthy), p, out) }
            }
        case .alt(let a, let b):
            var any = false
            try eval(a, v, p, env) { x, xp in
                if x.truthy {
                    any = true
                    try out(x, xp)
                }
            }
            if !any { try eval(b, v, p, env, out) }
        case .assign(let op, let lhs, let rhs):
            if p != nil { throw JQError("Invalid path expression with result of an assignment") }
            try assign(op, lhs, rhs, v, env, out)
        case .ifte(let branches, let els):
            try evalIf(branches[...], els, v, p, env, out)
        case .reduce(let src, let pat, let ini, let upd):
            try eval(ini, v, nil, env) { iv, _ in
                var acc = iv
                try self.eval(src, v, nil, env) { item, _ in
                    try self.bindPattern(pat, item, env) { e2 in
                        var last: JQValue? = nil
                        try self.eval(upd, acc, nil, e2) { u, _ in last = u }
                        acc = last ?? .null
                    }
                }
                try self.emitValue(acc, p, out)
            }
        case .foreach(let src, let pat, let ini, let upd, let ext):
            try eval(ini, v, nil, env) { iv, _ in
                var acc = iv
                try self.eval(src, v, nil, env) { item, _ in
                    try self.bindPattern(pat, item, env) { e2 in
                        try self.eval(upd, acc, nil, e2) { u, _ in
                            acc = u
                            if let ext {
                                try self.eval(ext, u, nil, e2) { x, _ in try self.emitValue(x, p, out) }
                            } else {
                                try self.emitValue(u, p, out)
                            }
                        }
                    }
                }
            }
        case .funcDef(let d, let rest):
            try eval(rest, v, p, JQEnv(env, .function(d)), out)
        case .call(let name, let args):
            try call(name, args, v, p, env, out)
        case .variable(let name):
            try emitValue(try lookupVar(name, env), p, out)
        case .bind(let src, let pat, let body):
            try eval(src, v, nil, env) { sv, _ in
                try self.bindPattern(pat, sv, env) { e2 in try self.eval(body, v, p, e2, out) }
            }
        case .label(let name, let body):
            let id = newID()
            do {
                try eval(body, v, p, JQEnv(env, .label(name, id)), out)
            } catch let b as JQBreak where b.id == id {
                return
            }
        case .breakLabel(let name):
            var e: JQEnv? = env
            while let cur = e {
                if case .label(let n, let id) = cur.entry, n == name { throw JQBreak(id: id) }
                e = cur.parent
            }
            throw JQError("$*label-\(name) is not defined")
        case .array(let e):
            var a: [JQValue] = []
            if let e { try eval(e, v, nil, env) { x, _ in a.append(x) } }
            try emitValue(.array(a), p, out)
        case .object(let entries):
            try buildObject(entries[...], JQObject(), v, env) { o in try self.emitValue(.object(o), p, out) }
        case .string(let parts, let fmt):
            try buildString(parts, parts.count - 1, "", v, env, fmt) { s in try self.emitValue(.string(s), p, out) }
        case .format(let name):
            try emitValue(.string(try JQOps.format(name, v)), p, out)
        }
    }

    private func recurseAll(_ v: JQValue, _ p: JQPath?, _ out: JQEmit) throws {
        try tick()
        if stackUsed() > stackBudget { throw JQAbort(reason: "recursion too deep") }
        try out(v, p)
        switch v {
        case .array(let a):
            for (i, e) in a.enumerated() { try recurseAll(e, p.map { $0 + [.num(i)] }, out) }
        case .object(let o):
            for k in o.keys { try recurseAll(o.dict[k]!, p.map { $0 + [.string(k)] }, out) }
        default:
            break
        }
    }

    private func tryEval(_ b: JQNode, _ h: JQNode?, _ v: JQValue, _ p: JQPath?, _ env: JQEnv, _ out: JQEmit) throws {
        let id = newID()
        do {
            try eval(b, v, p, env) { x, xp in
                do {
                    try out(x, xp)
                } catch let e as JQError {
                    throw JQPass(id: id, inner: e)
                }
            }
        } catch let e as JQError {
            guard let h else { return }
            try eval(h, e.value, nil, env) { x, _ in try self.emitValue(x, p, out) }
        } catch let e as JQPass where e.id == id {
            throw e.inner
        }
    }

    private func evalIf(_ bs: ArraySlice<(JQNode, JQNode)>, _ els: JQNode?, _ v: JQValue, _ p: JQPath?, _ env: JQEnv,
                        _ out: JQEmit) throws {
        guard let (c, t) = bs.first else {
            if let els { try eval(els, v, p, env, out) } else { try out(v, p) }
            return
        }
        try eval(c, v, nil, env) { cv, _ in
            if cv.truthy {
                try self.eval(t, v, p, env, out)
            } else {
                try self.evalIf(bs.dropFirst(), els, v, p, env, out)
            }
        }
    }

    func collectPaths(_ lhs: JQNode, _ v: JQValue, _ env: JQEnv) throws -> [JQPath] {
        var paths: [JQPath] = []
        try eval(lhs, v, [], env) { _, pp in paths.append(pp ?? []) }
        return paths
    }

    private func assign(_ op: JQAssignOp, _ lhs: JQNode, _ rhs: JQNode, _ v: JQValue, _ env: JQEnv, _ out: JQEmit) throws {
        switch op {
        case .update:
            // jq 1.7.1 _modify: the first output of the update replaces the value, no output deletes the path
            // (deletions applied together at the end)
            let paths = try collectPaths(lhs, v, env)
            var cur = v
            var dels: [JQPath] = []
            for path in paths {
                let old = try JQOps.getpath(cur, path)
                var first: JQValue? = nil
                let id = newID()
                do {
                    try eval(rhs, old, nil, env) { x, _ in
                        first = x
                        throw JQBreak(id: id)
                    }
                } catch let b as JQBreak where b.id == id {}
                if let nv = first { try JQOps.setpath(&cur, path[...], nv) } else { dels.append(path) }
            }
            if !dels.isEmpty { cur = try JQOps.delpaths(cur, dels) }
            try out(cur, nil)
        case .set:
            let paths = try collectPaths(lhs, v, env)
            try eval(rhs, v, nil, env) { x, _ in
                var cur = v
                for path in paths { try JQOps.setpath(&cur, path[...], x) }
                try out(cur, nil)
            }
        case .arith(let bop):
            let paths = try collectPaths(lhs, v, env)
            try eval(rhs, v, nil, env) { x, _ in
                var cur = v
                for path in paths {
                    let nv = try JQOps.binop(bop, try JQOps.getpath(cur, path), x)
                    try JQOps.setpath(&cur, path[...], nv)
                }
                try out(cur, nil)
            }
        case .alt:
            let paths = try collectPaths(lhs, v, env)
            try eval(rhs, v, nil, env) { x, _ in
                var cur = v
                for path in paths {
                    let old = try JQOps.getpath(cur, path)
                    try JQOps.setpath(&cur, path[...], old.truthy ? old : x)
                }
                try out(cur, nil)
            }
        }
    }

    func lookupVar(_ name: String, _ env: JQEnv) throws -> JQValue {
        var e: JQEnv? = env
        while let cur = e {
            if case .variable(let n, let x) = cur.entry, n == name { return x }
            e = cur.parent
        }
        if name == "ENV" { return .object(JQObject()) }
        throw JQError("$\(name) is not defined")
    }

    func call(_ name: String, _ args: [JQNode], _ v: JQValue, _ p: JQPath?, _ env: JQEnv, _ out: JQEmit) throws {
        depth += 1
        defer { depth -= 1 }
        if depth > Self.maxDepth || stackUsed() > stackBudget { throw JQAbort(reason: "recursion too deep") }
        let arity = args.count
        var e: JQEnv? = env
        while let cur = e {
            switch cur.entry {
            case .function(let d) where d.params.count == arity && d.name == name:
                try callUser(d, cur, args, v, p, env, out)
                return
            case .closure(let n, let body, let cenv) where arity == 0 && n == name:
                try eval(body, v, p, cenv, out)
                return
            default:
                break
            }
            e = cur.parent
        }
        let key = "\(name)/\(arity)"
        if let d = JQPrelude.defs[key] {
            try callUser(d, JQPrelude.rootEnv, args, v, p, env, out)
            return
        }
        if let f = JQBuiltins.table[key] {
            try f(self, args, v, p, env, out)
            return
        }
        throw JQError("\(key) is not defined")
    }

    private func callUser(_ d: JQFuncDef, _ defEnv: JQEnv, _ args: [JQNode], _ v: JQValue, _ p: JQPath?, _ callerEnv: JQEnv,
                          _ out: JQEmit) throws {
        if d.params.isEmpty {
            try eval(d.body, v, p, defEnv, out)
            return
        }
        try bindParams(d, 0, defEnv, args, v, p, callerEnv, out)
    }

    private func bindParams(_ d: JQFuncDef, _ i: Int, _ env: JQEnv, _ args: [JQNode], _ v: JQValue, _ p: JQPath?,
                            _ callerEnv: JQEnv, _ out: JQEmit) throws {
        if i == d.params.count {
            try eval(d.body, v, p, env, out)
            return
        }
        let prm = d.params[i]
        if prm.isVar {
            try eval(args[i], v, nil, callerEnv) { av, _ in
                let e1 = JQEnv(env, .variable(prm.name, av))
                let e2 = JQEnv(e1, .closure(prm.name, .literal(av), e1))
                try self.bindParams(d, i + 1, e2, args, v, p, callerEnv, out)
            }
        } else {
            try bindParams(d, i + 1, JQEnv(env, .closure(prm.name, args[i], callerEnv)), args, v, p, callerEnv, out)
        }
    }

    func bindPattern(_ pat: JQPattern, _ val: JQValue, _ env: JQEnv, _ k: (JQEnv) throws -> Void) throws {
        switch pat {
        case .variable(let n):
            try k(JQEnv(env, .variable(n, val)))
        case .array(let ps):
            try bindArray(ps[...], 0, val, env, k)
        case .object(let es):
            try bindObject(es[...], val, env, k)
        }
    }

    private func bindArray(_ ps: ArraySlice<JQPattern>, _ idx: Int, _ val: JQValue, _ env: JQEnv,
                           _ k: (JQEnv) throws -> Void) throws {
        guard let first = ps.first else { try k(env); return }
        switch val {
        case .array, .null: break
        default: throw JQError("Cannot index \(val.typeName) with number")
        }
        let elem = try JQOps.index(val, .num(idx))
        try bindPattern(first, elem, env) { e2 in try self.bindArray(ps.dropFirst(), idx + 1, val, e2, k) }
    }

    private func bindObject(_ es: ArraySlice<(key: JQObjKey, pattern: JQPattern?)>, _ val: JQValue, _ env: JQEnv,
                            _ k: (JQEnv) throws -> Void) throws {
        guard let e = es.first else { try k(env); return }
        let rest = es.dropFirst()
        func withKey(_ ks: String, _ bindVar: String?) throws {
            let x = try JQOps.index(val, .string(ks))
            var env2 = env
            if let bindVar { env2 = JQEnv(env, .variable(bindVar, x)) }
            if let sub = e.pattern {
                try bindPattern(sub, x, env2) { e3 in try self.bindObject(rest, val, e3, k) }
            } else {
                try bindObject(rest, val, env2, k)
            }
        }
        switch e.key {
        case .variable(let n):
            try withKey(n, n)
        case .name(let s):
            try withKey(s, nil)
        case .expr(let kn):
            try eval(kn, val, nil, env) { kv, _ in
                guard case .string(let ks) = kv else { throw JQError("Cannot index \(val.typeName) with \(kv.typeName)") }
                try withKey(ks, nil)
            }
        case .loc:
            throw JQError("Invalid object pattern")
        }
    }

    private func buildObject(_ es: ArraySlice<JQObjEntry>, _ acc: JQObject, _ v: JQValue, _ env: JQEnv,
                             _ k: (JQObject) throws -> Void) throws {
        guard let e = es.first else { try k(acc); return }
        let rest = es.dropFirst()
        func put(_ key: String, _ x: JQValue) throws {
            var o = acc
            o.set(key, x)
            try buildObject(rest, o, v, env, k)
        }
        switch e.key {
        case .name(let s):
            if let vn = e.value {
                try eval(vn, v, nil, env) { x, _ in try put(s, x) }
            } else {
                try put(s, try JQOps.index(v, .string(s)))
            }
        case .variable(let n):
            let val = try lookupVar(n, env)
            if let vn = e.value {
                guard case .string(let ks) = val else { throw JQError("Object keys must be strings") }
                try eval(vn, v, nil, env) { x, _ in try put(ks, x) }
            } else {
                try put(n, val)
            }
        case .loc(let line):
            try put("__loc__", Self.locValue(line))
        case .expr(let kn):
            try eval(kn, v, nil, env) { kv, _ in
                guard case .string(let ks) = kv else { throw JQError("Object keys must be strings") }
                if let vn = e.value {
                    try self.eval(vn, v, nil, env) { x, _ in try put(ks, x) }
                } else {
                    try put(ks, try JQOps.index(v, kv))
                }
            }
        }
    }

    private func buildString(_ parts: [JQStrPart], _ i: Int, _ suffix: String, _ v: JQValue, _ env: JQEnv, _ fmt: String?,
                             _ k: (String) throws -> Void) throws {
        if i < 0 { try k(suffix); return }
        switch parts[i] {
        case .lit(let t):
            try buildString(parts, i - 1, t + suffix, v, env, fmt, k)
        case .interp(let n):
            try eval(n, v, nil, env) { x, _ in
                let piece: String
                if let fmt {
                    piece = try JQOps.format(fmt, x)
                } else if case .string(let s) = x {
                    piece = s
                } else {
                    piece = JQOut.dump(x)
                }
                try self.buildString(parts, i - 1, piece + suffix, v, env, fmt, k)
            }
        }
    }
}

// MARK: - Operations

enum JQOps {
    static func isSlice(_ o: JQObject) -> Bool { o.count == 2 && o["start"] != nil && o["end"] != nil }

    static func sliceBounds(_ o: JQObject, _ len: Int) throws -> (Int, Int) {
        func num(_ x: JQValue?) throws -> Double? {
            switch x {
            case .number(let d, _)?: return d
            case .null?, nil: return nil
            default: throw JQError("Start and end indices of an array slice must be numbers")
            }
        }
        let l = Double(len)
        var ds = try num(o["start"]) ?? 0
        var de = try num(o["end"]) ?? l
        if ds.isNaN { ds = 0 }
        if de.isNaN { de = l }
        if ds < 0 { ds += l }
        if de < 0 { de += l }
        if ds < 0 { ds = 0 }
        if ds > l { ds = l }
        if de > l { de = l }
        if de < ds { de = ds }
        let s = JQNum.toInt(ds)
        var e = JQNum.toInt(de)
        if de > Double(e) { e += 1 }
        return (s, min(max(e, s), len))
    }

    static func index(_ v: JQValue, _ k: JQValue) throws -> JQValue {
        switch (v, k) {
        case (.object(let o), .string(let s)):
            return o[s] ?? .null
        case (.array(let a), .number(let d, _)):
            if d.isNaN { return .null }
            var i = JQNum.toInt(d.rounded(.down))
            if i < 0 { i += a.count }
            return (i >= 0 && i < a.count) ? a[i] : .null
        case (.null, .string), (.null, .number), (.null, .null), (.null, .array):
            return .null
        case (.null, .object(let o)) where isSlice(o):
            return .null
        case (.array(let a), .object(let o)) where isSlice(o):
            let (s, e) = try sliceBounds(o, a.count)
            return .array(Array(a[s..<e]))
        case (.string(let str), .object(let o)) where isSlice(o):
            let sc = Array(str.unicodeScalars)
            let (s, e) = try sliceBounds(o, sc.count)
            var u = String.UnicodeScalarView()
            u.append(contentsOf: sc[s..<e])
            return .string(String(u))
        case (.array(let a), .array(let b)):
            return indexes(a, b)
        default:
            break
        }
        if case .string(let s) = k { throw JQError("Cannot index \(v.typeName) with string \"\(s)\"") }
        throw JQError("Cannot index \(v.typeName) with \(k.typeName)")
    }

    static func indexes(_ a: [JQValue], _ b: [JQValue]) -> JQValue {
        var r: [JQValue] = []
        if b.isEmpty { return .array(r) }
        if a.count >= b.count {
            for i in 0...(a.count - b.count) {
                var ok = true
                for j in 0..<b.count where !JQValue.equal(a[i + j], b[j]) { ok = false; break }
                if ok { r.append(.num(i)) }
            }
        }
        return .array(r)
    }

    static func getpath(_ v: JQValue, _ path: JQPath) throws -> JQValue {
        var cur = v
        for k in path {
            if case .null = cur { return .null }
            cur = try index(cur, k)
        }
        return cur
    }

    /// setpath, mutating in place (the containers on the path are made unique first).
    static func setpath(_ v: inout JQValue, _ path: ArraySlice<JQValue>, _ x: JQValue) throws {
        guard let k = path.first else { v = x; return }
        let rest = path.dropFirst()
        switch k {
        case .string(let s):
            var o: JQObject
            switch v {
            case .null: o = JQObject()
            case .object(let ob): o = ob
            default: throw JQError("Cannot index \(v.typeName) with \"\(s)\"")
            }
            v = .null
            if var child = o.dict[s] {
                o.dict[s] = .null
                try setpath(&child, rest, x)
                o.dict[s] = child
            } else {
                var child = JQValue.null
                try setpath(&child, rest, x)
                o.set(s, child)
            }
            v = .object(o)
        case .number(let d, _):
            var a: [JQValue]
            switch v {
            case .null: a = []
            case .array(let arr): a = arr
            default: throw JQError("Cannot index \(v.typeName) with number")
            }
            var i = JQNum.toInt(d.rounded(.down))
            if i < 0 {
                i += a.count
                if i < 0 { throw JQError("Out of bounds negative array index") }
            }
            if i > 536_870_911 { throw JQError("Array index too large") }
            v = .null
            if i < a.count {
                var child = a[i]
                a[i] = .null
                try setpath(&child, rest, x)
                a[i] = child
            } else {
                var child = JQValue.null
                try setpath(&child, rest, x)
                a.append(contentsOf: repeatElement(JQValue.null, count: i - a.count))
                a.append(child)
            }
            v = .array(a)
        case .object(let o) where isSlice(o):
            var a: [JQValue]
            switch v {
            case .null: a = []
            case .array(let arr): a = arr
            default: throw JQError("Cannot update field at object index of \(v.typeName)")
            }
            let (s, e) = try sliceBounds(o, a.count)
            var sub = JQValue.array(Array(a[s..<e]))
            try setpath(&sub, rest, x)
            guard case .array(let na) = sub else { throw JQError("A slice of an array can only be assigned another array") }
            v = .null
            a.replaceSubrange(s..<e, with: na)
            v = .array(a)
        default:
            if case .null = v { throw JQError("Cannot index null with \(k.typeName)") }
            throw JQError("Cannot update field at object index of \(v.typeName)")
        }
    }

    static func delpaths(_ v: JQValue, _ paths: [JQPath]) throws -> JQValue {
        let sorted = paths.sorted { JQValue.cmp(.array($0), .array($1)) > 0 }
        var cur = v
        for p in sorted { try delpath(&cur, p[...]) }
        return cur
    }

    static func delpath(_ v: inout JQValue, _ path: ArraySlice<JQValue>) throws {
        guard let k = path.first else { v = .null; return }
        if case .null = v { return }
        let rest = path.dropFirst()
        if rest.isEmpty {
            switch (v, k) {
            case (.object(var o), .string(let s)):
                v = .null
                o.remove(s)
                v = .object(o)
            case (.array(var a), .number(let d, _)):
                v = .null
                var i = JQNum.toInt(d.rounded(.down))
                if i < 0 { i += a.count }
                if i >= 0 && i < a.count { a.remove(at: i) }
                v = .array(a)
            case (.array(var a), .object(let o)) where isSlice(o):
                let (s, e) = try sliceBounds(o, a.count)
                v = .null
                a.removeSubrange(s..<e)
                v = .array(a)
            case (.object, .number):
                throw JQError("Cannot delete number field of object")
            case (.array, .string):
                throw JQError("Cannot delete field at object index of array")
            default:
                throw JQError("Cannot delete field at index of \(v.typeName)")
            }
            return
        }
        switch (v, k) {
        case (.object(var o), .string(let s)):
            guard var child = o.dict[s] else { return }
            v = .null
            o.dict[s] = .null
            try delpath(&child, rest)
            o.dict[s] = child
            v = .object(o)
        case (.array(var a), .number(let d, _)):
            var i = JQNum.toInt(d.rounded(.down))
            if i < 0 { i += a.count }
            guard i >= 0 && i < a.count else { return }
            v = .null
            var child = a[i]
            a[i] = .null
            try delpath(&child, rest)
            a[i] = child
            v = .array(a)
        case (.array(var a), .object(let o)) where isSlice(o):
            let (s, e) = try sliceBounds(o, a.count)
            var sub = JQValue.array(Array(a[s..<e]))
            try delpath(&sub, rest)
            guard case .array(let na) = sub else { throw JQError("A slice of an array can only be assigned another array") }
            v = .null
            a.replaceSubrange(s..<e, with: na)
            v = .array(a)
        default:
            _ = try index(v, k)
        }
    }

    // MARK: arithmetic

    static func binop(_ op: JQBinOp, _ a: JQValue, _ b: JQValue) throws -> JQValue {
        switch op {
        case .add: return try add(a, b)
        case .sub:
            switch (a, b) {
            case (.number(let x, _), .number(let y, _)): return .num(x - y)
            case (.array(let x), .array(let y)): return .array(x.filter { e in !y.contains { JQValue.equal(e, $0) } })
            default: throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot be subtracted")
            }
        case .mul:
            switch (a, b) {
            case (.number(let x, _), .number(let y, _)): return .num(x * y)
            case (.string(let s), .number(let n, _)), (.number(let n, _), .string(let s)):
                if n.isNaN || n < 0 { return .null }
                let c = JQNum.toInt(n)
                if c == 0 { return .string("") }
                if c > 0 && s.utf8.count * c > 64 << 20 { throw JQError("Repeat string result too long") }
                return .string(String(repeating: s, count: c))
            case (.object(let x), .object(let y)): return .object(deepMerge(x, y))
            default: throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot be multiplied")
            }
        case .div:
            switch (a, b) {
            case (.number(let x, _), .number(let y, _)):
                if y == 0 { throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot be divided because the divisor is zero") }
                return .num(x / y)
            case (.string(let x), .string(let y)): return try split(x, y)
            default: throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot be divided")
            }
        case .mod:
            switch (a, b) {
            case (.number(let x, _), .number(let y, _)):
                let bi = JQNum.toInt(y)
                if bi == 0 { throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot be divided (remainder) because the divisor is zero") }
                let ai = JQNum.toInt(x)
                return .num(ai % Swift.abs(bi))
            default: throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot be divided (remainder)")
            }
        case .eq: return .bool(JQValue.cmp(a, b) == 0)
        case .ne: return .bool(JQValue.cmp(a, b) != 0)
        case .lt: return .bool(JQValue.cmp(a, b) < 0)
        case .le: return .bool(JQValue.cmp(a, b) <= 0)
        case .gt: return .bool(JQValue.cmp(a, b) > 0)
        case .ge: return .bool(JQValue.cmp(a, b) >= 0)
        }
    }

    static func add(_ a: JQValue, _ b: JQValue) throws -> JQValue {
        switch (a, b) {
        case (.null, _): return b
        case (_, .null): return a
        case (.number(let x, _), .number(let y, _)): return .num(x + y)
        case (.string(let x), .string(let y)): return .string(x + y)
        case (.array(let x), .array(let y)): return .array(x + y)
        case (.object(var x), .object(let y)):
            for k in y.keys { x.set(k, y.dict[k]!) }
            return .object(x)
        default:
            throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot be added")
        }
    }

    /// acc + x, reusing acc's storage (native add / join / from_entries).
    static func addInPlace(_ acc: inout JQValue, _ x: JQValue) throws {
        switch (acc, x) {
        case (.null, _): acc = x
        case (_, .null): return
        case (.array(var a), .array(let b)):
            acc = .null
            a.append(contentsOf: b)
            acc = .array(a)
        case (.string(var s), .string(let t)):
            acc = .null
            s += t
            acc = .string(s)
        case (.object(var o), .object(let y)):
            acc = .null
            for k in y.keys { o.set(k, y.dict[k]!) }
            acc = .object(o)
        default:
            acc = try add(acc, x)
        }
    }

    static func deepMerge(_ a: JQObject, _ b: JQObject) -> JQObject {
        var r = a
        for k in b.keys {
            let bv = b.dict[k]!
            if case .object(let bo) = bv, case .object(let ao)? = r[k] {
                r.set(k, .object(deepMerge(ao, bo)))
            } else {
                r.set(k, bv)
            }
        }
        return r
    }

    static func split(_ s: String, _ sep: String) throws -> JQValue {
        if s.isEmpty { return .array([]) }
        if sep.isEmpty { return .array(s.unicodeScalars.map { .string(String($0)) }) }
        let b = Array(s.utf8), p = Array(sep.utf8)
        var out: [JQValue] = []
        var start = 0, i = 0
        while i + p.count <= b.count {
            if b[i] == p[0] && Array(b[i..<(i + p.count)]) == p {
                out.append(.string(String(decoding: b[start..<i], as: UTF8.self)))
                i += p.count
                start = i
            } else {
                i += 1
            }
        }
        out.append(.string(String(decoding: b[start..<b.count], as: UTF8.self)))
        return .array(out)
    }

    static func length(_ v: JQValue) throws -> JQValue {
        switch v {
        case .null: return .num(0)
        case .bool: throw JQError("\(JQOut.typed(v)) has no length")
        case .number(let d, _): return .num(Swift.abs(d))
        case .string(let s): return .num(s.unicodeScalars.count)
        case .array(let a): return .num(a.count)
        case .object(let o): return .num(o.count)
        }
    }

    static func keys(_ v: JQValue, sorted: Bool) throws -> JQValue {
        switch v {
        case .object(let o): return .array((sorted ? o.sortedKeys : o.keys).map { .string($0) })
        case .array(let a): return .array((0..<a.count).map { .num($0) })
        default: throw JQError("\(JQOut.typed(v)) has no keys")
        }
    }

    static func has(_ v: JQValue, _ k: JQValue) throws -> JQValue {
        switch (v, k) {
        case (.object(let o), .string(let s)): return .bool(o[s] != nil)
        case (.array(let a), .number(let d, _)): return .bool(d >= 0 && d < Double(a.count))
        default: throw JQError("Cannot check whether \(v.typeName) has a \(k.typeName) key")
        }
    }

    static func contains(_ a: JQValue, _ b: JQValue) throws -> Bool {
        switch (a, b) {
        case (.object(let x), .object(let y)):
            for k in y.keys {
                guard let av = x[k], try contains(av, y.dict[k]!) else { return false }
            }
            return true
        case (.array(let x), .array(let y)):
            for be in y {
                var found = false
                for ae in x where try contains(ae, be) { found = true; break }
                if !found { return false }
            }
            return true
        case (.string(let x), .string(let y)):
            if y.isEmpty { return true }
            return x.range(of: y, options: .literal) != nil
        default:
            if a.rank == b.rank { return JQValue.equal(a, b) }
            throw JQError("\(JQOut.typed(a)) and \(JQOut.typed(b)) cannot have their containment checked")
        }
    }

    static func tostring(_ v: JQValue) -> String {
        if case .string(let s) = v { return s }
        return JQOut.dump(v)
    }

    static func iterate(_ v: JQValue) throws -> [JQValue] {
        switch v {
        case .array(let a): return a
        case .object(let o): return o.keys.map { o.dict[$0]! }
        default: throw JQError("Cannot iterate over \(JQOut.typed(v))")
        }
    }

    static func stableSort(_ a: [JQValue], keys: [JQValue]) -> [Int] {
        var idx = Array(0..<a.count)
        idx.sort { i, j in
            let c = JQValue.cmp(keys[i], keys[j])
            return c != 0 ? c < 0 : i < j
        }
        return idx
    }

    // MARK: formats

    static func format(_ name: String, _ v: JQValue) throws -> String {
        switch name {
        case "text": return tostring(v)
        case "json": return JQOut.dump(v)
        case "html":
            var o = ""
            for c in tostring(v).unicodeScalars {
                switch c {
                case "<": o += "&lt;"
                case ">": o += "&gt;"
                case "&": o += "&amp;"
                case "'": o += "&apos;"
                case "\"": o += "&quot;"
                default: o.unicodeScalars.append(c)
                }
            }
            return o
        case "uri":
            var o: [UInt8] = []
            let hex = Array("0123456789ABCDEF".utf8)
            for c in tostring(v).utf8 {
                let unreserved = (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39)
                    || c == UInt8(ascii: "-") || c == UInt8(ascii: "_") || c == UInt8(ascii: ".") || c == UInt8(ascii: "~")
                if unreserved { o.append(c) } else { o.append(contentsOf: [UInt8(ascii: "%"), hex[Int(c >> 4)], hex[Int(c & 0xF)]]) }
            }
            return String(decoding: o, as: UTF8.self)
        case "csv", "tsv":
            guard case .array(let a) = v else {
                throw JQError("\(JQOut.typed(v)) cannot be \(name)-formatted, only an array can be")
            }
            var parts: [String] = []
            for e in a {
                switch e {
                case .number: parts.append(JQOut.dump(e))
                case .bool(let b): parts.append(b ? "true" : "false")
                case .null: parts.append("")
                case .string(let s):
                    if name == "csv" {
                        parts.append("\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"")
                    } else {
                        var t = ""
                        for c in s.unicodeScalars {
                            switch c {
                            case "\\": t += "\\\\"
                            case "\t": t += "\\t"
                            case "\n": t += "\\n"
                            case "\r": t += "\\r"
                            default: t.unicodeScalars.append(c)
                            }
                        }
                        parts.append(t)
                    }
                default:
                    throw JQError("\(JQOut.typed(e)) is not valid in a \(name) row")
                }
            }
            return parts.joined(separator: name == "csv" ? "," : "\t")
        case "sh":
            func q(_ e: JQValue) throws -> String {
                switch e {
                case .string(let s): return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
                case .array, .object: throw JQError("\(JQOut.typed(e)) can not be escaped for shell")
                default: return JQOut.dump(e)
                }
            }
            if case .array(let a) = v { return try a.map(q).joined(separator: " ") }
            return try q(v)
        case "base64":
            return Data(tostring(v).utf8).base64EncodedString()
        case "base64d":
            var s = tostring(v).filter { !$0.isWhitespace }
            while s.hasSuffix("=") { s.removeLast() }
            let pad = (4 - s.utf8.count % 4) % 4
            if pad == 3 { throw JQError("\(JQOut.typed(v)) is not valid base64 data") }
            guard let d = Data(base64Encoded: s + String(repeating: "=", count: pad)) else {
                throw JQError("\(JQOut.typed(v)) is not valid base64 data")
            }
            return String(decoding: d, as: UTF8.self)
        default:
            throw JQError("\(name) is not a valid format")
        }
    }
}

// MARK: - Regex (jq uses Oniguruma; ICU via NSRegularExpression is the closest pure-Foundation engine)

enum JQRegex {
    struct Compiled {
        let re: NSRegularExpression
        let names: [String?]      // per capture group (index 0 = group 1)
        let global: Bool
        let skipEmpty: Bool
    }

    private static let lock = NSLock()
    private static var cache: [String: Compiled] = [:]

    static func compile(_ pattern: String, _ flags: String?) throws -> Compiled {
        let f = flags ?? ""
        let key = f + "\u{0}" + pattern
        lock.lock()
        if let c = cache[key] { lock.unlock(); return c }
        lock.unlock()
        var opts: NSRegularExpression.Options = []
        var global = false, skipEmpty = false
        for c in f {
            switch c {
            case "g": global = true
            case "i": opts.insert(.caseInsensitive)
            case "x": opts.insert(.allowCommentsAndWhitespace)
            case "n": skipEmpty = true
            case "p": opts.insert(.dotMatchesLineSeparators)
            case "s", "l": break
            default: throw JQError("\(f) is not a valid modifier string")
            }
        }
        let re: NSRegularExpression
        do {
            re = try NSRegularExpression(pattern: pattern.isEmpty ? "(?:)" : pattern, options: opts)
        } catch {
            throw JQError("\(pattern) (at offset 0) is not a valid regex")
        }
        let c = Compiled(re: re, names: groupNames(pattern, re.numberOfCaptureGroups), global: global, skipEmpty: skipEmpty)
        lock.lock()
        if cache.count > 256 { cache.removeAll() }
        cache[key] = c
        lock.unlock()
        return c
    }

    /// Capture group names in group order: '(' opens a capture unless followed by '?' (then only (?<name> /
    /// (?P<name> / (?'name' capture).
    static func groupNames(_ p: String, _ n: Int) -> [String?] {
        var names: [String?] = []
        let s = Array(p.utf8)
        var i = 0
        var inClass = false
        while i < s.count {
            let c = s[i]
            if c == UInt8(ascii: "\\") { i += 2; continue }
            if inClass {
                if c == UInt8(ascii: "]") { inClass = false }
                i += 1
                continue
            }
            if c == UInt8(ascii: "[") { inClass = true; i += 1; if i < s.count && s[i] == UInt8(ascii: "]") { i += 1 }; continue }
            if c == UInt8(ascii: "(") {
                if i + 1 < s.count && s[i + 1] == UInt8(ascii: "?") {
                    var j = i + 2
                    if j < s.count && s[j] == UInt8(ascii: "P") { j += 1 }
                    if j < s.count && (s[j] == UInt8(ascii: "<") || s[j] == UInt8(ascii: "'")),
                       j + 1 < s.count, s[j + 1] != UInt8(ascii: "="), s[j + 1] != UInt8(ascii: "!") {
                        let close: UInt8 = s[j] == UInt8(ascii: "<") ? UInt8(ascii: ">") : UInt8(ascii: "'")
                        var k = j + 1
                        while k < s.count && s[k] != close { k += 1 }
                        names.append(String(decoding: s[(j + 1)..<min(k, s.count)], as: UTF8.self))
                    }
                } else {
                    names.append(nil)
                }
            }
            i += 1
        }
        while names.count < n { names.append(nil) }
        if names.count > n { names = Array(names.prefix(n)) }
        return names
    }

    struct Subject {
        let s: String
        let ns: NSString
        let map: [Int]?   // utf16 offset → codepoint offset (nil: ASCII)

        init(_ s: String) {
            self.s = s
            ns = s as NSString
            if s.utf8.count == ns.length {
                map = nil
            } else {
                var m: [Int] = []
                m.reserveCapacity(ns.length + 1)
                var cp = 0
                for u in s.unicodeScalars {
                    m.append(cp)
                    if u.value > 0xFFFF { m.append(cp) }
                    cp += 1
                }
                m.append(cp)
                map = m
            }
        }

        func cp(_ u16: Int) -> Int { map.map { u16 < $0.count ? $0[u16] : $0.last ?? u16 } ?? u16 }
    }

    static func matches(_ subj: Subject, _ c: Compiled, forceGlobal: Bool = false) -> [NSTextCheckingResult] {
        let full = NSRange(location: 0, length: subj.ns.length)
        var out: [NSTextCheckingResult] = []
        if c.global || forceGlobal {
            for m in c.re.matches(in: subj.s, options: [], range: full) {
                if c.skipEmpty && m.range.length == 0 { continue }
                out.append(m)
            }
        } else {
            for m in c.re.matches(in: subj.s, options: [], range: full) {
                if c.skipEmpty && m.range.length == 0 { continue }
                out.append(m)
                break
            }
        }
        return out
    }

    static func matchObject(_ m: NSTextCheckingResult, _ subj: Subject, _ names: [String?]) -> JQValue {
        var o = JQObject()
        let st = subj.cp(m.range.location)
        o.set("offset", .num(st))
        o.set("length", .num(subj.cp(m.range.location + m.range.length) - st))
        o.set("string", .string(subj.ns.substring(with: m.range)))
        var caps: [JQValue] = []
        if m.numberOfRanges > 1 {
            for g in 1..<m.numberOfRanges {
                let r = m.range(at: g)
                let name: JQValue = (g - 1 < names.count ? names[g - 1] : nil).map { .string($0) } ?? .null
                var c = JQObject()
                if r.location == NSNotFound {
                    c.set("offset", .num(-1))
                    c.set("string", .null)
                    c.set("length", .num(0))
                    c.set("name", name)
                } else {
                    let cs = subj.cp(r.location)
                    c.set("offset", .num(cs))
                    c.set("length", .num(subj.cp(r.location + r.length) - cs))
                    c.set("string", .string(subj.ns.substring(with: r)))
                    c.set("name", name)
                }
                caps.append(.object(c))
            }
        }
        o.set("captures", .array(caps))
        return .object(o)
    }

    static func captureObject(_ m: NSTextCheckingResult, _ subj: Subject, _ names: [String?]) -> JQObject {
        var o = JQObject()
        if m.numberOfRanges > 1 {
            for g in 1..<m.numberOfRanges {
                guard g - 1 < names.count, let n = names[g - 1] else { continue }
                let r = m.range(at: g)
                o.set(n, r.location == NSNotFound ? .null : .string(subj.ns.substring(with: r)))
            }
        }
        return o
    }
}

// MARK: - Builtins

enum JQBuiltins {
    typealias Native = (JQInterp, [JQNode], JQValue, JQPath?, JQEnv, JQEmit) throws -> Void

    static func f0(_ f: @escaping (JQValue) throws -> JQValue) -> Native {
        return { it, _, v, p, _, out in try it.emitValue(try f(v), p, out) }
    }

    static func f1(_ f: @escaping (JQValue, JQValue) throws -> JQValue) -> Native {
        return { it, args, v, p, env, out in
            try it.eval(args[0], v, nil, env) { a, _ in try it.emitValue(try f(v, a), p, out) }
        }
    }

    static func f2(_ f: @escaping (JQValue, JQValue, JQValue) throws -> JQValue) -> Native {
        return { it, args, v, p, env, out in
            try it.eval(args[0], v, nil, env) { a, _ in
                try it.eval(args[1], v, nil, env) { b, _ in try it.emitValue(try f(v, a, b), p, out) }
            }
        }
    }

    static func math(_ f: @escaping (Double) -> Double) -> Native {
        f0 { v in
            guard case .number(let d, _) = v else { throw JQError("\(JQOut.typed(v)) number required") }
            return .num(f(d))
        }
    }

    static func str(_ v: JQValue, _ what: String) throws -> String {
        guard case .string(let s) = v else { throw JQError("\(JQOut.typed(v)) \(what)") }
        return s
    }

    static func regexArgs(_ re: JQValue, _ flags: JQValue) throws -> (String, String?) {
        var r = re, f = flags
        if case .array(let a) = re {
            r = a.first ?? .null
            if a.count > 1 { f = a[1] }
        }
        guard case .string(let rs) = r else { throw JQError("\(JQOut.typed(r)) cannot be matched, as it is not a string") }
        switch f {
        case .null: return (rs, nil)
        case .string(let fs): return (rs, fs)
        default: throw JQError("\(JQOut.typed(f)) is not a string")
        }
    }

    static func subject(_ v: JQValue) throws -> JQRegex.Subject {
        guard case .string(let s) = v else { throw JQError("\(JQOut.typed(v)) cannot be matched, as it is not a string") }
        return JQRegex.Subject(s)
    }

    /// match/test/capture/scan/split with optional flags argument
    static func regex(_ arity: Int, _ body: @escaping (JQRegex.Subject, JQRegex.Compiled, JQEmit) throws -> Void,
                      forceGlobal: Bool = false) -> Native {
        return { it, args, v, p, env, out in
            func emit(_ x: JQValue, _ q: JQPath?) throws { try it.emitValue(x, p, out) }
            try it.eval(args[0], v, nil, env) { re, _ in
                func run(_ fl: JQValue) throws {
                    let (rs, fs) = try regexArgs(re, fl)
                    let subj = try subject(v)
                    var flags = fs
                    if forceGlobal { flags = "g" + (fs ?? "") }
                    try body(subj, try JQRegex.compile(rs, flags), emit)
                }
                if arity == 2 {
                    try it.eval(args[1], v, nil, env) { fl, _ in try run(fl) }
                } else {
                    try run(.null)
                }
            }
        }
    }

    static func sub(global: Bool) -> Native {
        return { it, args, v, p, env, out in
            guard case .string(let s) = v else { throw JQError("\(JQOut.typed(v)) cannot be matched, as it is not a string") }
            try it.eval(args[0], v, nil, env) { re, _ in
                func run(_ fl: JQValue) throws {
                    let (rs, fs) = try regexArgs(re, fl)
                    let c = try JQRegex.compile(rs, global ? "g" + (fs ?? "") : fs)
                    let subj = JQRegex.Subject(s)
                    let ms = JQRegex.matches(subj, c)
                    func build(_ i: Int, _ acc: String, _ prev: Int) throws {
                        if i == ms.count {
                            try it.emitValue(.string(acc + subj.ns.substring(from: prev)), p, out)
                            return
                        }
                        let m = ms[i]
                        let gap = subj.ns.substring(with: NSRange(location: prev, length: max(0, m.range.location - prev)))
                        let caps = JQValue.object(JQRegex.captureObject(m, subj, c.names))
                        try it.eval(args[1], caps, nil, env) { rep, _ in
                            let piece = try JQOps.add(.string(acc + gap), rep)
                            guard case .string(let ps) = piece else { throw JQError("\(JQOut.typed(rep)) cannot be added to a string") }
                            try build(i + 1, ps, m.range.location + m.range.length)
                        }
                    }
                    try build(0, "", 0)
                }
                if args.count == 3 {
                    try it.eval(args[2], v, nil, env) { fl, _ in try run(fl) }
                } else {
                    try run(.null)
                }
            }
        }
    }

    static func minmax(_ v: JQValue, _ keys: [JQValue]?, isMin: Bool) throws -> JQValue {
        guard case .array(let a) = v else { throw JQError("\(JQOut.typed(v)) cannot be iterated over") }
        if a.isEmpty { return .null }
        let ks = keys ?? a
        var best = 0
        for i in 1..<a.count {
            let c = JQValue.cmp(ks[i], ks[best])
            if isMin ? (c < 0) : (c >= 0) { best = i }
        }
        return a[best]
    }

    static func keyList(_ v: JQValue, _ k: JQValue, _ what: String) throws -> ([JQValue], [JQValue]) {
        guard case .array(let a) = v else { throw JQError("\(JQOut.typed(v)) cannot be \(what), as it is not an array") }
        guard case .array(let ks) = k, ks.count == a.count else { throw JQError("\(what): keys mismatch") }
        return (a, ks)
    }

    static func strIndices(_ s: String, _ t: String) -> JQValue {
        let b = Array(s.utf8), p = Array(t.utf8)
        if p.isEmpty { return .null }
        var r: [JQValue] = []
        var i = 0
        while i + p.count <= b.count {
            if b[i] == p[0] && Array(b[i..<(i + p.count)]) == p { r.append(.num(i)) }
            i += 1
        }
        return .array(r)
    }

    static func indices(_ v: JQValue, _ i: JQValue) throws -> JQValue {
        switch (v, i) {
        case (.array(let a), .array(let b)): return JQOps.indexes(a, b)
        case (.array(let a), _): return JQOps.indexes(a, [i])
        case (.string(let s), .string(let t)): return strIndices(s, t)
        case (.null, _): return .null
        default:
            return try JQOps.index(v, .array([i]))
        }
    }

    static func flatten(_ a: [JQValue], _ depth: Double, into out: inout [JQValue]) {
        for e in a {
            if case .array(let sub) = e, depth != 0 {
                flatten(sub, depth - 1, into: &out)
            } else {
                out.append(e)
            }
        }
    }

    static func fromEntries(_ v: JQValue) throws -> JQValue {
        var o = JQObject()
        for x in try JQOps.iterate(v) {
            var key = JQValue.null
            for name in ["key", "Key", "name", "Name"] {
                key = try JQOps.index(x, .string(name))
                if key.truthy { break }
            }
            guard case .string(let ks) = key else { throw JQError("Cannot use \(JQOut.typed(key)) as object key") }
            let value: JQValue
            if case .null = x {
                throw JQError("Cannot check whether null has a string key")
            } else if try JQOps.has(x, .string("value")).truthy {
                value = try JQOps.index(x, .string("value"))
            } else {
                value = try JQOps.index(x, .string("Value"))
            }
            o.set(ks, value)
        }
        return .object(o)
    }

    static func range(_ it: JQInterp, _ from: JQValue, _ upto: JQValue, _ by: JQValue, _ p: JQPath?, _ out: JQEmit) throws {
        guard case .number(let f, _) = from, case .number(let u, _) = upto, case .number(let b, _) = by else {
            throw JQError("Range bounds must be numeric")
        }
        if b > 0 {
            var x = f
            var first = true
            while x < u {
                try it.tick()
                try it.emitValue(first ? from : .num(x), p, out)
                first = false
                x += b
            }
        } else if b < 0 {
            var x = f
            var first = true
            while x > u {
                try it.tick()
                try it.emitValue(first ? from : .num(x), p, out)
                first = false
                x += b
            }
        }
    }

    static let table: [String: Native] = {
        var t: [String: Native] = [:]
        t["empty/0"] = { _, _, _, _, _, _ in }
        t["error/0"] = { _, _, v, _, _, _ in throw JQError(v) }
        t["error/1"] = { it, args, v, _, env, _ in
            try it.eval(args[0], v, nil, env) { m, _ in throw JQError(m) }
        }
        t["not/0"] = f0 { .bool(!$0.truthy) }
        t["length/0"] = f0(JQOps.length)
        t["utf8bytelength/0"] = f0 { v in .num(try str(v, "only strings have UTF-8 byte length").utf8.count) }
        t["keys/0"] = f0 { try JQOps.keys($0, sorted: true) }
        t["keys_unsorted/0"] = f0 { try JQOps.keys($0, sorted: false) }
        t["type/0"] = f0 { .string($0.typeName) }
        t["tostring/0"] = f0 { .string(JQOps.tostring($0)) }
        t["tojson/0"] = f0 { .string(JQOut.dump($0)) }
        t["fromjson/0"] = f0 { v in
            let s = try str(v, "only strings can be parsed")
            do { return try JQJSONParser.parse(s) } catch let e as JQError {
                throw JQError("\(e.message) (while parsing '\(s)')")
            }
        }
        t["tonumber/0"] = f0 { v in
            switch v {
            case .number: return v
            case .string(let s):
                let trimmed = s.trimmingCharacters(in: .whitespaces)
                var x: JQValue
                do { x = try JQJSONParser.parse(trimmed) } catch let e as JQError {
                    throw JQError("\(e.message) (while parsing '\(s)')")
                }
                guard case .number = x else { throw JQError("Cannot parse '\(s)' as a number") }
                return x
            default:
                throw JQError("\(JQOut.typed(v)) cannot be parsed as a number")
            }
        }
        t["ascii_downcase/0"] = f0 { v in
            guard case .string(let s) = v else { throw JQError("explode input must be a string") }
            return .string(String(decoding: s.utf8.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 32 : $0 }, as: UTF8.self))
        }
        t["ascii_upcase/0"] = f0 { v in
            guard case .string(let s) = v else { throw JQError("explode input must be a string") }
            return .string(String(decoding: s.utf8.map { $0 >= 0x61 && $0 <= 0x7A ? $0 - 32 : $0 }, as: UTF8.self))
        }
        t["explode/0"] = f0 { v in
            guard case .string(let s) = v else { throw JQError("explode input must be a string") }
            return .array(s.unicodeScalars.map { .num(Int($0.value)) })
        }
        t["implode/0"] = f0 { v in
            guard case .array(let a) = v else { throw JQError("implode input must be an array") }
            var u = String.UnicodeScalarView()
            for e in a {
                guard case .number(let d, _) = e else {
                    throw JQError("\(JQOut.typed(e)) can't be imploded, unicode codepoint needs to be numeric")
                }
                let i = JQNum.toInt(d)
                u.append((i >= 0 && i <= 0x10FFFF ? Unicode.Scalar(UInt32(i)) : nil) ?? Unicode.Scalar(0xFFFD)!)
            }
            return .string(String(u))
        }
        t["floor/0"] = math { $0.rounded(.down) }
        t["ceil/0"] = math { $0.rounded(.up) }
        t["round/0"] = math { $0.rounded(.toNearestOrAwayFromZero) }
        t["trunc/0"] = math { $0.rounded(.towardZero) }
        t["fabs/0"] = math { Swift.abs($0) }
        t["sqrt/0"] = math { $0.squareRoot() }
        t["log/0"] = math { Foundation.log($0) }
        t["log2/0"] = math { Foundation.log2($0) }
        t["log10/0"] = math { Foundation.log10($0) }
        t["exp/0"] = math { Foundation.exp($0) }
        t["exp2/0"] = math { Foundation.exp2($0) }
        t["exp10/0"] = math { Foundation.pow(10, $0) }
        t["pow/2"] = f2 { _, a, b in
            guard case .number(let x, _) = a, case .number(let y, _) = b else { throw JQError("pow requires numbers") }
            return .num(Foundation.pow(x, y))
        }
        t["infinite/0"] = f0 { _ in .num(Double.infinity) }
        t["nan/0"] = f0 { _ in .num(Double.nan) }
        t["isinfinite/0"] = f0 { v in
            guard case .number(let d, _) = v else { throw JQError("\(JQOut.typed(v)) number required") }
            return .bool(d.isInfinite)
        }
        t["isnan/0"] = f0 { v in
            guard case .number(let d, _) = v else { throw JQError("\(JQOut.typed(v)) number required") }
            return .bool(d.isNaN)
        }
        t["isnormal/0"] = f0 { v in
            guard case .number(let d, _) = v else { throw JQError("\(JQOut.typed(v)) number required") }
            return .bool(d.isNormal)
        }
        t["now/0"] = f0 { _ in .num(Date().timeIntervalSince1970) }
        t["input_filename/0"] = f0 { _ in .null }
        t["input/0"] = { _, _, _, _, _, _ in throw JQError("No more inputs") }
        t["inputs/0"] = { _, _, _, _, _, _ in throw JQError("No more inputs") }
        t["debug/0"] = f0 { $0 }
        t["stderr/0"] = f0 { $0 }
        t["sort/0"] = f0 { v in
            guard case .array(let a) = v else { throw JQError("\(JQOut.typed(v)) cannot be sorted, as it is not an array") }
            return .array(JQOps.stableSort(a, keys: a).map { a[$0] })
        }
        t["unique/0"] = f0 { v in
            guard case .array(let a) = v else { throw JQError("\(JQOut.typed(v)) cannot be sorted, as it is not an array") }
            var r: [JQValue] = []
            for i in JQOps.stableSort(a, keys: a) where r.isEmpty || !JQValue.equal(r[r.count - 1], a[i]) { r.append(a[i]) }
            return .array(r)
        }
        t["_sort_by_impl/1"] = f1 { v, k in
            let (a, ks) = try keyList(v, k, "sorted")
            return .array(JQOps.stableSort(a, keys: ks).map { a[$0] })
        }
        t["_group_by_impl/1"] = f1 { v, k in
            let (a, ks) = try keyList(v, k, "grouped")
            var groups: [JQValue] = []
            var cur: [JQValue] = []
            var last: JQValue? = nil
            for i in JQOps.stableSort(a, keys: ks) {
                if let l = last, JQValue.equal(l, ks[i]) {
                    cur.append(a[i])
                } else {
                    if last != nil { groups.append(.array(cur)) }
                    cur = [a[i]]
                    last = ks[i]
                }
            }
            if last != nil { groups.append(.array(cur)) }
            return .array(groups)
        }
        t["_min_by_impl/1"] = f1 { v, k in
            let (_, ks) = try keyList(v, k, "iterated over")
            return try minmax(v, ks, isMin: true)
        }
        t["_max_by_impl/1"] = f1 { v, k in
            let (_, ks) = try keyList(v, k, "iterated over")
            return try minmax(v, ks, isMin: false)
        }
        t["min/0"] = f0 { try minmax($0, nil, isMin: true) }
        t["max/0"] = f0 { try minmax($0, nil, isMin: false) }
        t["add/0"] = f0 { v in
            var acc = JQValue.null
            for e in try JQOps.iterate(v) { try JQOps.addInPlace(&acc, e) }
            return acc
        }
        t["join/1"] = f1 { v, sep in
            var acc = JQValue.null
            for e in try JQOps.iterate(v) {
                let piece: JQValue
                switch e {
                case .null: piece = .string("")
                case .string: piece = e
                default: piece = .string(JQOut.dump(e))
                }
                if case .null = acc { acc = .string("") } else { try JQOps.addInPlace(&acc, sep) }
                try JQOps.addInPlace(&acc, piece)
            }
            if !acc.truthy { return .string("") }
            return acc
        }
        t["flatten/0"] = f0 { v in
            var out: [JQValue] = []
            flatten(try JQOps.iterate(v), -1, into: &out)
            return .array(out)
        }
        t["flatten/1"] = f1 { v, d in
            guard case .number(let depth, _) = d else { throw JQError("flatten depth must not be negative") }
            if depth < 0 { throw JQError("flatten depth must not be negative") }
            var out: [JQValue] = []
            flatten(try JQOps.iterate(v), depth, into: &out)
            return .array(out)
        }
        t["to_entries/0"] = f0 { v in
            switch v {
            case .object(let o):
                return .array(o.keys.map { k in
                    var e = JQObject()
                    e.set("key", .string(k))
                    e.set("value", o.dict[k]!)
                    return .object(e)
                })
            case .array(let a):
                return .array(a.enumerated().map { i, x in
                    var e = JQObject()
                    e.set("key", .num(i))
                    e.set("value", x)
                    return .object(e)
                })
            default:
                throw JQError("\(JQOut.typed(v)) has no keys")
            }
        }
        t["from_entries/0"] = f0(fromEntries)
        t["has/1"] = f1(JQOps.has)
        t["contains/1"] = f1 { .bool(try JQOps.contains($0, $1)) }
        t["split/1"] = f1 { v, s in
            guard case .string(let a) = v, case .string(let b) = s else { throw JQError("split input and separator must be strings") }
            return try JQOps.split(a, b)
        }
        t["ltrimstr/1"] = f1 { v, x in
            if case .string(let s) = v, case .string(let pre) = x, s.utf8.starts(with: pre.utf8) {
                return .string(String(decoding: Array(s.utf8.dropFirst(pre.utf8.count)), as: UTF8.self))
            }
            return v
        }
        t["rtrimstr/1"] = f1 { v, x in
            if case .string(let s) = v, case .string(let suf) = x, s.utf8.count >= suf.utf8.count,
               Array(s.utf8.suffix(suf.utf8.count)) == Array(suf.utf8) {
                return .string(String(decoding: Array(s.utf8.dropLast(suf.utf8.count)), as: UTF8.self))
            }
            return v
        }
        t["startswith/1"] = f1 { v, x in
            guard case .string(let s) = v, case .string(let pre) = x else { throw JQError("startswith() requires string inputs") }
            return .bool(s.utf8.starts(with: pre.utf8))
        }
        t["endswith/1"] = f1 { v, x in
            guard case .string(let s) = v, case .string(let suf) = x else { throw JQError("endswith() requires string inputs") }
            return .bool(s.utf8.count >= suf.utf8.count && Array(s.utf8.suffix(suf.utf8.count)) == Array(suf.utf8))
        }
        t["indices/1"] = f1(indices)
        t["index/1"] = f1 { v, i in
            let r = try indices(v, i)
            if case .array(let a) = r { return a.first ?? .null }
            return .null
        }
        t["rindex/1"] = f1 { v, i in
            let r = try indices(v, i)
            if case .array(let a) = r { return a.last ?? .null }
            return .null
        }
        t["getpath/1"] = { it, args, v, p, env, out in
            try it.eval(args[0], v, nil, env) { pa, _ in
                guard case .array(let path) = pa else { throw JQError("Path must be specified as an array") }
                let r = try JQOps.getpath(v, path)
                try out(r, p.map { $0 + path })
            }
        }
        t["setpath/2"] = f2 { v, pa, x in
            guard case .array(let path) = pa else { throw JQError("Path must be specified as an array") }
            var cur = v
            try JQOps.setpath(&cur, path[...], x)
            return cur
        }
        t["delpaths/1"] = f1 { v, ps in
            guard case .array(let list) = ps else { throw JQError("Paths must be specified as an array") }
            var paths: [JQPath] = []
            for e in list {
                guard case .array(let path) = e else { throw JQError("Path must be specified as an array") }
                paths.append(path)
            }
            return try JQOps.delpaths(v, paths)
        }
        t["path/1"] = { it, args, v, p, env, out in
            try it.eval(args[0], v, [], env) { _, pp in try it.emitValue(.array(pp ?? []), p, out) }
        }
        t["range/1"] = { it, args, v, p, env, out in
            try it.eval(args[0], v, nil, env) { n, _ in try range(it, .num(0), n, .num(1), p, out) }
        }
        t["range/2"] = { it, args, v, p, env, out in
            try it.eval(args[0], v, nil, env) { f, _ in
                try it.eval(args[1], v, nil, env) { u, _ in try range(it, f, u, .num(1), p, out) }
            }
        }
        t["range/3"] = { it, args, v, p, env, out in
            try it.eval(args[0], v, nil, env) { f, _ in
                try it.eval(args[1], v, nil, env) { u, _ in
                    try it.eval(args[2], v, nil, env) { b, _ in try range(it, f, u, b, p, out) }
                }
            }
        }
        t["limit/2"] = { it, args, v, p, env, out in
            try it.eval(args[0], v, nil, env) { nv, _ in
                guard case .number(let n, _) = nv else { throw JQError("Invalid limit: \(JQOut.typed(nv))") }
                if n <= 0 {
                    if n < 0 { try it.eval(args[1], v, p, env, out) }
                    return
                }
                var count = 0.0
                let id = it.newID()
                do {
                    try it.eval(args[1], v, p, env) { x, xp in
                        count += 1
                        try out(x, xp)
                        if count >= n { throw JQBreak(id: id) }
                    }
                } catch let b as JQBreak where b.id == id {}
            }
        }
        t["first/1"] = { it, args, v, p, env, out in
            let id = it.newID()
            do {
                try it.eval(args[0], v, p, env) { x, xp in
                    try out(x, xp)
                    throw JQBreak(id: id)
                }
            } catch let b as JQBreak where b.id == id {}
        }
        t["test/1"] = regex(1, { subj, c, emit in try emit(.bool(!JQRegex.matches(subj, c).isEmpty), nil) })
        t["test/2"] = regex(2, { subj, c, emit in try emit(.bool(!JQRegex.matches(subj, c).isEmpty), nil) })
        let matchBody: (JQRegex.Subject, JQRegex.Compiled, JQEmit) throws -> Void = { subj, c, emit in
            for m in JQRegex.matches(subj, c) { try emit(JQRegex.matchObject(m, subj, c.names), nil) }
        }
        t["match/1"] = regex(1, matchBody)
        t["match/2"] = regex(2, matchBody)
        let captureBody: (JQRegex.Subject, JQRegex.Compiled, JQEmit) throws -> Void = { subj, c, emit in
            for m in JQRegex.matches(subj, c) { try emit(.object(JQRegex.captureObject(m, subj, c.names)), nil) }
        }
        t["capture/1"] = regex(1, captureBody)
        t["capture/2"] = regex(2, captureBody)
        let scanBody: (JQRegex.Subject, JQRegex.Compiled, JQEmit) throws -> Void = { subj, c, emit in
            for m in JQRegex.matches(subj, c, forceGlobal: true) {
                if m.numberOfRanges > 1 {
                    var caps: [JQValue] = []
                    for g in 1..<m.numberOfRanges {
                        let r = m.range(at: g)
                        caps.append(r.location == NSNotFound ? .null : .string(subj.ns.substring(with: r)))
                    }
                    try emit(.array(caps), nil)
                } else {
                    try emit(.string(subj.ns.substring(with: m.range)), nil)
                }
            }
        }
        t["scan/1"] = regex(1, scanBody, forceGlobal: true)
        t["scan/2"] = regex(2, scanBody, forceGlobal: true)
        t["split/2"] = regex(2, { subj, c, emit in
            var bounds = [0]
            for m in JQRegex.matches(subj, c, forceGlobal: true) {
                bounds.append(m.range.location)
                bounds.append(m.range.location + m.range.length)
            }
            bounds.append(subj.ns.length)
            var parts: [JQValue] = []
            var i = 0
            while i + 1 < bounds.count {
                let s = bounds[i], e = max(bounds[i + 1], bounds[i])
                parts.append(.string(subj.ns.substring(with: NSRange(location: s, length: e - s))))
                i += 2
            }
            try emit(.array(parts), nil)
        }, forceGlobal: true)
        t["sub/2"] = sub(global: false)
        t["sub/3"] = sub(global: false)
        t["gsub/2"] = sub(global: true)
        t["gsub/3"] = sub(global: true)
        return t
    }()
}

// MARK: - jq-defined builtins (jq 1.7.1 builtin.jq semantics)

enum JQPrelude {
    static let source = """
    def values: select(. != null);
    def nulls: select(. == null);
    def booleans: select(type == "boolean");
    def numbers: select(type == "number");
    def strings: select(type == "string");
    def arrays: select(type == "array");
    def objects: select(type == "object");
    def iterables: select(type|. == "array" or . == "object");
    def scalars: select(type|. != "array" and . != "object");
    def finites: select(isinfinite or isnan | not);
    def normals: select(isnormal);
    def map(f): [.[] | f];
    def select(f): if f then . else empty end;
    def recurse(f): def r: ., (f | r); r;
    def recurse(f; cond): def r: ., (f | select(cond) | r); r;
    def recurse: recurse(.[]?);
    def sort_by(f): _sort_by_impl(map([f]));
    def group_by(f): _group_by_impl(map([f]));
    def unique_by(f): [group_by(f)[] | .[0]];
    def max_by(f): _max_by_impl(map([f]));
    def min_by(f): _min_by_impl(map([f]));
    def del(f): delpaths([path(f)]);
    def map_values(f): .[] |= f;
    def with_entries(f): to_entries | map(f) | from_entries;
    def paths: path(..) | select(length > 0);
    def paths(node_filter): . as $dot | paths | select(. as $p | $dot | getpath($p) | node_filter);
    def any: reduce .[] as $x (false; . or $x);
    def all: reduce .[] as $x (true; . and $x);
    def any(f): reduce (.[] | f) as $x (false; . or $x);
    def all(f): reduce (.[] | f) as $x (true; . and $x);
    def isempty(g): first((g | false), true);
    def any(g; cond): isempty(first(g | cond or empty)) | not;
    def all(g; cond): isempty(first(g | cond and empty));
    def in(xs): . as $x | xs | has($x);
    def inside(xs): . as $x | xs | contains($x);
    def combinations: if length == 0 then [] else .[0][] as $x | (.[1:] | combinations) as $w | [$x] + $w end;
    def combinations(n): . as $dot | [range(n)] | map($dot) | combinations;
    def walk(f): def w: if type == "object" then map_values(w) elif type == "array" then map(w) else . end | f; w;
    def env: $ENV;
    def first: .[0];
    def last: .[-1];
    def nth($n): .[$n];
    def last(f): reduce f as $x (null; $x);
    def nth($n; f): if $n < 0 then error("nth doesn't support negative indices") else last(limit($n + 1; f)) end;
    def until(cond; update): def _until: if cond then . else (update | _until) end; _until;
    def while(cond; update): def _while: if cond then ., (update | _while) else empty end; _while;
    def repeat(f): def _repeat: f, _repeat; _repeat;
    def IN(s): any(s == .; .);
    def IN(src; s): any(src == s; .);
    def INDEX(stream; idx_expr): reduce stream as $row ({}; .[$row | idx_expr | tostring] |= $row);
    def INDEX(idx_expr): INDEX(.[]; idx_expr);
    def tostream: path(def r: (.[]? | r), .; r) as $p | getpath($p) | reduce path(.[]?) as $q ([$p, .]; [$p + $q]);
    def pick(pathexps): . as $top | reduce path(pathexps) as $p (null; setpath($p; $top | getpath($p)));
    def debug(msg): (msg | debug | empty), .;
    def reverse: [.[length - 1 - range(0; length)]];
    def splits($re): splits($re; null);
    def splits($re; flags): split($re; flags) | .[];
    def abs: if type == "number" and . < 0 then - . else . end;
    def todate: error("todate is not supported");
    .
    """

    static let rootEnv = JQEnv(nil, .root)

    static let defs: [String: JQFuncDef] = {
        var d: [String: JQFuncDef] = [:]
        guard var n = try? JQParser.parse(source) else { return d }
        while case .funcDef(let f, let rest) = n {
            d[f.key] = f
            n = rest
        }
        return d
    }()
}

// MARK: - Compile-time name resolution

final class JQScope {
    enum Kind { case fn(String), variable(String), label(String) }
    let parent: JQScope?
    let kind: Kind?

    init(_ parent: JQScope?, _ kind: Kind?) {
        self.parent = parent
        self.kind = kind
    }

    func has(fn key: String) -> Bool {
        var s: JQScope? = self
        while let c = s {
            if case .fn(let k)? = c.kind, k == key { return true }
            s = c.parent
        }
        return JQPrelude.defs[key] != nil || JQBuiltins.table[key] != nil
    }

    func has(variable n: String) -> Bool {
        if n == "ENV" { return true }
        var s: JQScope? = self
        while let c = s {
            if case .variable(let k)? = c.kind, k == n { return true }
            s = c.parent
        }
        return false
    }

    func has(label n: String) -> Bool {
        var s: JQScope? = self
        while let c = s {
            if case .label(let k)? = c.kind, k == n { return true }
            s = c.parent
        }
        return false
    }
}

enum JQResolver {
    static func patternVars(_ p: JQPattern, _ sc: JQScope) throws -> JQScope {
        switch p {
        case .variable(let n): return JQScope(sc, .variable(n))
        case .array(let ps):
            var s = sc
            for x in ps { s = try patternVars(x, s) }
            return s
        case .object(let es):
            var s = sc
            for e in es {
                switch e.key {
                case .variable(let n): s = JQScope(s, .variable(n))
                case .expr(let k): try resolve(k, sc)
                default: break
                }
                if let sub = e.pattern { s = try patternVars(sub, s) }
            }
            return s
        }
    }

    static func resolve(_ n: JQNode, _ sc: JQScope) throws {
        switch n {
        case .identity, .recurseAll, .literal, .loc, .format:
            return
        case .index(let a, let b), .pipe(let a, let b), .comma(let a, let b), .binop(_, let a, let b), .and(let a, let b),
             .or(let a, let b), .alt(let a, let b), .assign(_, let a, let b):
            try resolve(a, sc)
            try resolve(b, sc)
        case .slice(let t, let f, let to):
            try resolve(t, sc)
            if let f { try resolve(f, sc) }
            if let to { try resolve(to, sc) }
        case .iterate(let a), .optional(let a), .neg(let a):
            try resolve(a, sc)
        case .ifte(let bs, let e):
            for (c, t) in bs {
                try resolve(c, sc)
                try resolve(t, sc)
            }
            if let e { try resolve(e, sc) }
        case .tryCatch(let b, let h):
            try resolve(b, sc)
            if let h { try resolve(h, sc) }
        case .reduce(let src, let pat, let ini, let upd):
            try resolve(src, sc)
            try resolve(ini, sc)
            try resolve(upd, try patternVars(pat, sc))
        case .foreach(let src, let pat, let ini, let upd, let ext):
            try resolve(src, sc)
            try resolve(ini, sc)
            let s2 = try patternVars(pat, sc)
            try resolve(upd, s2)
            if let ext { try resolve(ext, s2) }
        case .funcDef(let d, let rest):
            let s1 = JQScope(sc, .fn(d.key))
            var sb = s1
            for prm in d.params {
                if prm.isVar { sb = JQScope(sb, .variable(prm.name)) }
                sb = JQScope(sb, .fn("\(prm.name)/0"))
            }
            try resolve(d.body, sb)
            try resolve(rest, s1)
        case .call(let name, let args):
            if !sc.has(fn: "\(name)/\(args.count)") { throw JQCompileError(message: "\(name)/\(args.count) is not defined") }
            for a in args { try resolve(a, sc) }
        case .variable(let name):
            if !sc.has(variable: name) { throw JQCompileError(message: "$\(name) is not defined") }
        case .bind(let src, let pat, let body):
            try resolve(src, sc)
            try resolve(body, try patternVars(pat, sc))
        case .label(let name, let body):
            try resolve(body, JQScope(sc, .label(name)))
        case .breakLabel(let name):
            if !sc.has(label: name) { throw JQCompileError(message: "$*label-\(name) is not defined") }
        case .array(let e):
            if let e { try resolve(e, sc) }
        case .object(let es):
            for e in es {
                switch e.key {
                case .expr(let k): try resolve(k, sc)
                case .variable(let v): if !sc.has(variable: v) { throw JQCompileError(message: "$\(v) is not defined") }
                default: break
                }
                if let v = e.value { try resolve(v, sc) }
            }
        case .string(let parts, let fmt):
            if let fmt, !["text", "json", "html", "uri", "csv", "tsv", "sh", "base64", "base64d"].contains(fmt) {
                throw JQCompileError(message: "\(fmt) is not a valid format")
            }
            for case .interp(let e) in parts { try resolve(e, sc) }
        }
    }
}

// MARK: - Public entry points

enum NativeJQ {
    final class Program {
        let source: String
        let root: JQNode
        init(source: String, root: JQNode) {
            self.source = source
            self.root = root
        }
    }

    /// Default per-run budget.
    static var budget: TimeInterval = 0.5
    /// Stack of the evaluation thread (the generator recursion is deep on nested JSON).
    static let stackSize = 16 << 20

    static func compile(_ src: String) throws -> Program {
        let trimmed = src.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { throw JQCompileError(message: "empty filter") }
        let root = try JQParser.parse(src)
        try JQResolver.resolve(root, JQScope(nil, nil))
        return Program(source: src, root: root)
    }

    enum Outcome {
        case output(JQValue)
        case empty
        case failed(String)
    }

    private final class Box: @unchecked Sendable { var outcome: Outcome = .empty }

    /// The first output of the program on input (all outputs when `all`), on a large-stack thread.
    static func run(_ p: Program, input: JQValue, budget: TimeInterval? = nil) -> Outcome {
        let box = Box()
        let b = budget ?? Self.budget
        let work = {
            box.outcome = runHere(p, input: input, budget: b)
        }
        let sem = DispatchSemaphore(value: 0)
        let t = Thread {
            work()
            sem.signal()
        }
        t.stackSize = stackSize
        t.name = "tern.jq"
        t.start()
        sem.wait()
        return box.outcome
    }

    /// Runs on the calling thread (tests / callers that already have a big stack).
    static func runHere(_ p: Program, input: JQValue, budget: TimeInterval) -> Outcome {
        let it = JQInterp(budget: budget)
        var result: Outcome = .empty
        let id = it.newID()
        do {
            try it.eval(p.root, input, nil, JQPrelude.rootEnv) { x, _ in
                result = .output(x)
                throw JQBreak(id: id)
            }
        } catch let b as JQBreak where b.id == id {
        } catch let e as JQError {
            return .failed(e.message)
        } catch let e as JQPass {
            return .failed(e.inner.message)
        } catch let e as JQAbort {
            return .failed(e.reason)
        } catch is JQBreak {
            return .failed("break outside its label")
        } catch {
            return .failed("\(error)")
        }
        return result
    }

    /// Every output (tests): [outputs] or the error message after the outputs produced before it.
    static func runAll(_ p: Program, input: JQValue, budget: TimeInterval = 5) -> (outputs: [JQValue], error: String?) {
        final class AllBox: @unchecked Sendable { var outs: [JQValue] = []; var err: String? }
        let box = AllBox()
        let sem = DispatchSemaphore(value: 0)
        let t = Thread {
            let it = JQInterp(budget: budget)
            do {
                try it.eval(p.root, input, nil, JQPrelude.rootEnv) { x, _ in box.outs.append(x) }
            } catch let e as JQError {
                box.err = e.message
            } catch let e as JQPass {
                box.err = e.inner.message
            } catch let e as JQAbort {
                box.err = e.reason
            } catch {
                box.err = "\(error)"
            }
            sem.signal()
        }
        t.stackSize = stackSize
        t.start()
        sem.wait()
        return (box.outs, box.err)
    }

    enum BodyResult {
        case body(Data)
        case skip(String)
    }

    /// A body rewrite: the body parsed as JSON, the program run, the first output written as compact JSON — all on
    /// the large-stack thread (parsing and encoding recurse with the nesting too).
    /// Not JSON / an error / no output → skip (the caller keeps the body as it was and logs a warning).
    static func apply(_ p: Program, body: Data, budget: TimeInterval? = nil) -> BodyResult {
        final class ResultBox: @unchecked Sendable { var r: BodyResult = .skip("not run") }
        let box = ResultBox()
        let b = budget ?? Self.budget
        let sem = DispatchSemaphore(value: 0)
        let t = Thread {
            defer { sem.signal() }
            let input: JQValue
            do { input = try JQJSONParser.parse(body) } catch {
                box.r = .skip("body is not JSON")
                return
            }
            switch runHere(p, input: input, budget: b) {
            case .output(let v): box.r = .body(JQOut.dumpData(v))
            case .empty: box.r = .skip("filter produced no output")
            case .failed(let m): box.r = .skip(m)
            }
        }
        t.stackSize = stackSize
        t.name = "tern.jq"
        t.start()
        sem.wait()
        return box.r
    }
}
