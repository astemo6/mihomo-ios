// Tern script host prelude (v0.19.22, feat/jsc-engine). ONE source for every script engine: goja (Go: tests,
// Android, fallback) and JavaScriptCore (iOS tunnel, PacketTunnel/JSCScriptEngine.swift) both evaluate this
// file, so the Surge / Loon / Quantumult X / Egern API behaves the same whichever engine runs the script.
//
// The engine provides three primitives on the global object `__tern` (non-enumerable):
//   __tern.host(op, arg)         -> string      synchronous call into the Go host (script.go hostOp)
//   __tern.put(ab, off, len)     -> number      hands bytes of an ArrayBuffer to the host, returns a blob id
//   __tern.take(id)              -> Uint8Array  a fresh copy of a host blob (own ArrayBuffer, offset 0)
// and the host calls three entry points defined here:
//   __tern_begin(setupJSON)      installs a run's globals ($request, $done, …); a JSC context that is reused
//                                for the next run of the same script is reset to the globals it had after
//                                this prelude first (globals a script created are deleted)
//   __tern_fire(timerId)         a setTimeout / setInterval timer fired
//   __tern_deliver(json)         an async host answer ($httpClient, $task.fetch, $httpAPI callback)
// Engine-specific code stays out of this file.
(function (G) {
  'use strict';
  var T = G.__tern;
  var host = T.host, putRaw = T.put, take = T.take;
  var R = null; // current run state (one run per context at a time)

  function isObj(v) { return v !== null && (typeof v === 'object' || typeof v === 'function'); }
  function nn(x) { return x === undefined || x === null ? undefined : x; }
  function get(o, k) { return nn(o[k]); }
  function argStr(v) { return v === undefined || v === null ? '' : String(v); }
  function toInteger(x) {
    var n = Number(x);
    if (n !== n) return 0;
    if (n > 1e15) return 1e15;
    if (n < -1e15) return -1e15;
    return n < 0 ? Math.ceil(n) : Math.floor(n);
  }
  function define(o, k, v) { Object.defineProperty(o, k, { value: v, writable: true, enumerable: false, configurable: true }); }

  // jsString: how console / $persistentStore turn a value into text (strings as they are, Error as
  // "Name: message", objects as JSON).
  function jsString(v) {
    if (v === undefined) return 'undefined';
    if (v === null) return 'null';
    if (typeof v === 'string') return v;
    if (isObj(v)) {
      if (v instanceof Error) return String(v);
      if (typeof v !== 'function') {
        try { var s = JSON.stringify(v); if (s !== undefined) return s; } catch (e) { /* cycle: String() below */ }
      }
    }
    return String(v);
  }

  // ---- bytes ----
  // putBytes: final = the bytes a finished run hands back ($done); an engine whose buffers live in the host's
  // heap may keep them instead of copying (goja), others ignore the flag.
  function putBytes(v, final) {
    if (v instanceof ArrayBuffer) return putRaw(v, 0, v.byteLength, !!final);
    return putRaw(v.buffer, v.byteOffset, v.byteLength, !!final);
  }
  function utf8Blob(s) { return +host('utf8', String(s)); }
  // toBlob: a body value → host blob id (-1 = none). string → UTF-8; ArrayBuffer / typed array / DataView →
  // its bytes; anything else → JSON (String() when JSON has no text for it).
  function toBlob(v, final) {
    if (v === undefined || v === null) return -1;
    if (typeof v === 'string') return utf8Blob(v);
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return putBytes(v, final);
    var s;
    try { s = JSON.stringify(v); } catch (e) { s = undefined; }
    return utf8Blob(s === undefined ? String(v) : s);
  }
  function blobText(id) { return host('text', String(id)); }

  // ---- case-insensitive headers ($request.headers, $response.headers, $httpClient responses) ----
  // Keys keep the case they first had, values whatever the script stored; assigning undefined deletes.
  function ciHeaders(pairs) {
    var keys = [], vals = Object.create(null), orig = Object.create(null);
    function put(k, v) {
      var lk = k.toLowerCase();
      if (!(lk in orig)) { keys.push(k); orig[lk] = k; }
      vals[lk] = v;
    }
    function del(k) {
      var lk = k.toLowerCase();
      if (lk in orig) {
        var o = orig[lk];
        delete vals[lk]; delete orig[lk];
        var i = keys.indexOf(o);
        if (i >= 0) keys.splice(i, 1);
      }
    }
    for (var i = 0; i < pairs.length; i++) put(pairs[i][0], pairs[i][1]);
    return new Proxy({}, {
      get: function (t, p, r) {
        if (typeof p === 'string') { var lk = p.toLowerCase(); if (lk in vals) return vals[lk]; }
        return Reflect.get(t, p, r);
      },
      set: function (t, p, v) {
        if (typeof p !== 'string') { t[p] = v; return true; }
        if (v === undefined) del(p); else put(p, v);
        return true;
      },
      has: function (t, p) { return (typeof p === 'string' && (p.toLowerCase() in vals)) || (p in t); },
      deleteProperty: function (t, p) { if (typeof p === 'string') del(p); else delete t[p]; return true; },
      ownKeys: function () { return keys.slice(); },
      getOwnPropertyDescriptor: function (t, p) {
        if (typeof p !== 'string') return undefined;
        var lk = p.toLowerCase();
        if (!(lk in vals)) return undefined;
        return { value: vals[lk], writable: true, enumerable: true, configurable: true };
      },
      defineProperty: function (t, p, d) {
        if (typeof p === 'string' && d && 'value' in d) { if (d.value === undefined) del(p); else put(p, d.value); return true; }
        return false;
      }
    });
  }
  // headerPairs: a headers value from a script → [[name, value]…] (arrays give one line per element).
  function headerPairs(x) {
    var o = Object(x), out = [], ks = Object.keys(o);
    for (var i = 0; i < ks.length; i++) {
      var k = ks[i], val = o[k];
      if (val === undefined || val === null) continue;
      if (Array.isArray(val)) { for (var j = 0; j < val.length; j++) out.push([k, String(val[j])]); continue; }
      out.push([k, String(val)]);
    }
    return out;
  }

  // ---- bodies on $request / $response ----
  // binary-body-mode: body is a Uint8Array and bodyBytes the ArrayBuffer under it.
  // Text mode (v0.19.22): body and bodyBytes are both lazy accessors — body enumerable (`{...$response}` and
  // JSON.stringify still see it), bodyBytes not (Quantumult X scripts read it) — so a protobuf script that only
  // reads bodyBytes never builds the text (a 3 MB binary body as text is several times larger), and
  // $done($response) with a body the script never touched hands nothing back: the host keeps its bytes.
  // borrow (large bodies, engines whose take() can map the host's bytes): the phase body's own buffer handed
  // back returns the original blob instead of a copy; a body changed in place but not handed back (error, no
  // $done body) is restored by the host (handler.go).
  function setBody(obj, blob, binary, borrow) {
    R.bodyObj = obj; R.bodyBlob = blob; R.borrow = !!borrow;
    if (binary) {
      var u8 = take(blob);
      obj.body = u8; obj.bodyBytes = u8.buffer;
      R.origBody = u8; R.origBB = u8.buffer; R.hasOrigBB = true;
      return;
    }
    var L = { str: undefined, hasStr: false, strSet: false, origStr: undefined, ab: undefined, hasAB: false, abSet: false };
    L.getBody = function () {
      if (!L.hasStr) { L.str = blobText(blob); L.hasStr = true; L.origStr = L.str; R.origBody = L.str; }
      return L.str;
    };
    R.lazy = L;
    Object.defineProperty(obj, 'body', {
      get: L.getBody,
      set: function (v) { L.str = v; L.hasStr = true; L.strSet = true; },
      enumerable: true, configurable: true
    });
    Object.defineProperty(obj, 'bodyBytes', {
      get: function () {
        if (!L.hasAB) { L.ab = take(blob).buffer; L.hasAB = true; R.origBB = L.ab; R.hasOrigBB = true; }
        return L.ab;
      },
      set: function (v) { L.ab = v; L.hasAB = true; L.abSet = true; },
      enumerable: false, configurable: true
    });
  }

  // ---- $done → descriptor the host turns into the rewrite (script.go parseDone) ----
  function statusOf(x) { return x === undefined ? null : (typeof x === 'number' ? x : String(x)); }
  // bodyBlob: a body value the run hands back. The phase body's own borrowed buffer (whole) is the original blob.
  function bodyBlob(v) {
    if (R.borrow && R.hasOrigBB && R.bodyBlob >= 0 && (v === R.origBB ||
        (ArrayBuffer.isView(v) && v.buffer === R.origBB && v.byteOffset === 0 && v.byteLength === R.origBB.byteLength))) {
      return R.bodyBlob;
    }
    return toBlob(v, true);
  }
  // lazyDone: doneBody for the text-mode phase object itself, without materialising what the script never
  // touched. undefined: not that object, or its body accessor was replaced (delete / defineProperty).
  function lazyDone(o) {
    var L = R.lazy;
    if (!L || o !== R.bodyObj) return undefined;
    var desc = Object.getOwnPropertyDescriptor(o, 'body');
    if (!desc || desc.get !== L.getBody) return undefined;
    var bb = L.hasAB ? nn(L.ab) : undefined, body;
    if (L.strSet && !(L.origStr !== undefined && L.str === L.origStr)) body = nn(L.str);
    if (bb !== undefined && body !== undefined && !L.abSet) bb = undefined; // untouched original bytes lose to a changed body
    if (bb !== undefined) return bodyBlob(bb);
    if (body !== undefined) return toBlob(body, true);
    return -1; // untouched, or set back to the original text: the host keeps its bytes
  }
  function doneBody(o) {
    var r = lazyDone(o);
    if (r !== undefined) return r;
    var bb = get(o, 'bodyBytes'), body = get(o, 'body');
    // $done($response) after `$response.body = x`: the untouched original bodyBytes must not win.
    if (bb !== undefined && body !== undefined && R.hasOrigBB && bb === R.origBB && (R.origBody === undefined || body !== R.origBody)) bb = undefined;
    if (bb !== undefined) return bodyBlob(bb);
    if (body !== undefined) {
      // the original text unchanged (e.g. `$done({...$response})`): the original bytes, no copy
      if (typeof body === 'string' && typeof R.origBody === 'string' && R.bodyBlob >= 0 && body === R.origBody) return R.bodyBlob;
      return bodyBlob(body);
    }
    return -1;
  }
  function doneDesc(v) {
    if (!isObj(v)) return { kind: 'none' };
    var d = { kind: 'obj' };
    var a = get(v, '__egernAbort');
    if (a !== undefined && a) { d.abort = true; return d; }
    if (R.phase === 'request') {
      var mock = get(v, 'response');
      if (mock === undefined && R.echo && (get(v, 'status') !== undefined || get(v, 'body') !== undefined || get(v, 'bodyBytes') !== undefined)) mock = v;
      // A request script answering the QX way ($done({status, headers, body})) is a local answer.
      if (mock === undefined && (get(v, 'status') !== undefined || get(v, 'statusCode') !== undefined) && get(v, 'url') === undefined && get(v, 'method') === undefined) mock = v;
      if (mock !== undefined) {
        var mo = Object(mock);
        var m = { status: statusOf(get(mo, 'status')), statusCode: statusOf(get(mo, 'statusCode')) };
        var mh = get(mo, 'headers');
        if (mh !== undefined) m.headers = headerPairs(mh);
        var b = get(mo, 'bodyBytes');
        if (b === undefined) b = get(mo, 'body');
        m.body = b === undefined ? -1 : toBlob(b);
        d.mock = m;
        return d;
      }
      var u = get(v, 'url'); if (u !== undefined) d.url = String(u);
      var me = get(v, 'method'); if (me !== undefined) d.method = String(me);
    } else if (R.phase === 'response') {
      d.status = statusOf(get(v, 'status'));
      d.statusCode = statusOf(get(v, 'statusCode'));
    }
    var h = get(v, 'headers');
    if (h !== undefined) d.headers = headerPairs(h);
    d.body = doneBody(v);
    return d;
  }
  // exportValue: JSON-safe copy of a $done value (task results, 脚本调试); binary → {__ternBinary: size}.
  function exportValue(v, depth, seen) {
    if (v === undefined || typeof v === 'function' || typeof v === 'symbol') return undefined;
    if (v === null) return null;
    if (typeof v === 'number') return isFinite(v) ? v : null;
    if (typeof v === 'bigint') return String(v);
    if (typeof v !== 'object') return v;
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return { __ternBinary: v.byteLength };
    if (v instanceof Date) return isNaN(v.getTime()) ? null : v.toISOString();
    if (depth > 30 || seen.indexOf(v) >= 0) return null;
    seen.push(v);
    var out, i, x;
    if (Array.isArray(v)) {
      out = [];
      for (i = 0; i < v.length; i++) { x = exportValue(v[i], depth + 1, seen); out.push(x === undefined ? null : x); }
    } else {
      out = {};
      var ks = Object.keys(v);
      for (i = 0; i < ks.length; i++) { x = exportValue(v[ks[i]], depth + 1, seen); if (x !== undefined) out[ks[i]] = x; }
    }
    seen.pop();
    return out;
  }

  // ---- async answers ----
  function reg(fn) { var id = ++R.cbID; R.cbs[id] = fn; return id; }

  // parseFetch: $httpClient (method set) / $task.fetch (method "") options → request for the host.
  function parseFetch(method, v) {
    if (v === undefined || v === null) return { err: '缺少请求参数' };
    var fr = { method: method, headers: [], body: -1, timeout: 0, binary: false, policy: '', insecure: false, noRedirect: false };
    if (typeof v === 'string') { fr.url = v; if (!fr.method) fr.method = 'GET'; return fr; }
    var o = Object(v), x;
    if ((x = get(o, 'url')) !== undefined) fr.url = String(x);
    if ((x = get(o, 'method')) !== undefined && method === '') fr.method = String(x).toUpperCase();
    if (!fr.method) fr.method = 'GET';
    if ((x = get(o, 'headers')) !== undefined) fr.headers = headerPairs(x);
    if ((x = get(o, 'body')) !== undefined) fr.body = toBlob(x);
    else if ((x = get(o, 'bodyBytes')) !== undefined) fr.body = toBlob(x);
    if ((x = get(o, 'timeout')) !== undefined) {
      var t = Number(x);
      // QX ($task.fetch) documents milliseconds, Surge ($httpClient) seconds; large Surge values are ms in practice.
      if (t > 0) fr.timeout = (method === '' || t > 1000) ? Math.floor(t) : t * 1000;
    }
    if ((x = get(o, 'binary-mode')) !== undefined) fr.binary = !!x;
    if ((x = get(o, 'policy')) !== undefined) fr.policy = String(x);
    if ((x = get(o, 'insecure')) !== undefined) fr.insecure = !!x;
    if ((x = get(o, 'auto-redirect')) !== undefined && !x) fr.noRedirect = true;
    if ((x = get(o, 'opts')) !== undefined) {
      var oo = Object(x);
      if (oo.policy !== undefined) fr.policy = String(oo.policy);
      if (oo.redirection !== undefined && !oo.redirection) fr.noRedirect = true;
    }
    if (!fr.url) return { err: '缺少 url' };
    return fr;
  }
  function httpClient(method) {
    return function (opts, cb) {
      var fr = parseFetch(method, opts);
      if (fr.err !== undefined) { if (typeof cb === 'function') cb(fr.err, null, null); return undefined; }
      var binary = fr.binary;
      fr.id = reg(function (d) {
        if (typeof cb !== 'function') return;
        if (d.err !== undefined) { cb(d.err, null, null); return; }
        var ro = { status: d.status, statusCode: d.status, headers: ciHeaders(d.headers) };
        var data = binary ? take(d.body) : blobText(d.body);
        ro.body = data;
        cb(null, ro, data);
      });
      host('http', JSON.stringify(fr));
      return undefined;
    };
  }
  function taskFetch(opts) {
    return new Promise(function (resolve, reject) {
      var fr = parseFetch('', opts);
      if (fr.err !== undefined) { reject({ error: fr.err }); return; }
      fr.id = reg(function (d) {
        if (d.err !== undefined) { reject({ error: d.err }); return; }
        resolve({ statusCode: d.status, status: d.status, headers: ciHeaders(d.headers), body: blobText(d.body), bodyBytes: take(d.body).buffer });
      });
      host('http', JSON.stringify(fr));
    });
  }

  // ---- URL / URLSearchParams (lazy: the polyfill runs on first use of either name) ----
  // The WHATWG-style implementation is urlPolyfillJS (urlglobal.go), spliced in by PreludeSource.
  function __ternURLPolyfill() { return /*URL_POLYFILL*/; }
  var urlLib = null;
  function installURL() {
    ['URL', 'URLSearchParams'].forEach(function (n) {
      Object.defineProperty(G, n, {
        get: function () {
          if (!urlLib) urlLib = __ternURLPolyfill();
          var v = urlLib[n];
          define(G, n, v); // replace the accessor by the value (scripts may overwrite it with their own polyfill)
          return v;
        },
        set: function (v) { define(G, n, v); },
        enumerable: false, configurable: true
      });
    });
  }

  // ---- reset between runs of a reused context ----
  var BASE = null;
  function reset() {
    if (!BASE) return;
    var names = Object.getOwnPropertyNames(G);
    for (var i = 0; i < names.length; i++) {
      if (!BASE[names[i]]) { try { delete G[names[i]]; } catch (e) { /* non-configurable var of a script: stays */ } }
    }
  }

  function install(S) {
    var name = S.name;
    G.$done = function (v) {
      if (R.done) return undefined;
      R.done = true;
      var d;
      try { d = doneDesc(v); } catch (e) { d = { kind: 'none', err: String(e) }; }
      if (R.wantExport) {
        d.undef = v === undefined;
        d.isNull = v === null;
        try { d.value = exportValue(v, 0, []); } catch (e2) { d.value = null; }
      }
      host('done', JSON.stringify(d));
      return undefined;
    };
    var A = S.arg;
    if (A.has && A.obj) {
      // JSON.parse keeps the plugin's key order.
      var av;
      try { av = JSON.parse(A.s); } catch (e) { av = undefined; }
      G.$argument = (av !== null && typeof av === 'object' && Object.prototype.toString.call(av) === '[object Object]') ? av : A.s;
    } else if (A.has) {
      G.$argument = A.s;
    } else {
      G.$argument = undefined; // declared, so `if ($argument)` does not throw
    }
    G.$script = { name: name, type: S.type, startTime: new Date(), path: S.path };
    var env = S.env;
    if (S.hasParams) env.params = S.params;
    G.$environment = env;

    var con = {};
    ['log', 'info', 'warn', 'error', 'debug'].forEach(function (lv) {
      con[lv] = function () {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) parts.push(jsString(arguments[i]));
        host('log', lv + '\n' + parts.join(' '));
        return undefined;
      };
    });
    G.console = con;

    function addTimer(args, repeat) {
      var fn = args[0];
      if (typeof fn !== 'function') return undefined;
      var ms = toInteger(args[1]);
      if (ms < 0) ms = 0;
      if (repeat && ms < 10) ms = 10;
      var id = ++R.timerID;
      R.timers[id] = { fn: fn, args: Array.prototype.slice.call(args, 2), repeat: repeat };
      host('timer', id + ',' + ms + ',' + (repeat ? 1 : 0));
      return id;
    }
    function clearTimer(x) {
      var id = toInteger(x);
      if (R.timers[id]) { delete R.timers[id]; host('clear', String(id)); }
      return undefined;
    }
    G.setTimeout = function () { return addTimer(arguments, false); };
    G.setInterval = function () { return addTimer(arguments, true); };
    G.clearTimeout = clearTimer;
    G.clearInterval = clearTimer;

    // $persistentStore (Surge / Loon) / $prefs (QX)
    function sread(k) { var r = host('sread', k); return r.charAt(0) === '1' ? r.slice(1) : undefined; }
    function swrite(k, v, del) { return host('swrite', (del ? 'd' : 'w') + k.length + ':' + k + v) === 'true'; }
    function keyFor(v) { return (v === undefined || v === null || String(v) === '') ? '@script:' + name : String(v); }
    G.$persistentStore = {
      read: function (k) { var v = sread(keyFor(k)); return v === undefined ? null : v; },
      write: function (v, k) { var del = v === undefined || v === null; return swrite(keyFor(k), del ? '' : jsString(v), del); }
    };
    G.$prefs = {
      valueForKey: function (k) { return sread(String(k)); },
      setValueForKey: function (v, k) { return swrite(String(k), jsString(v), false); },
      removeValueForKey: function (k) { return swrite(String(k), '', true); },
      removeAllValues: function () { return host('sclear', '') === 'true'; }
    };

    function optURL(v) {
      if (v === undefined || v === null) return '';
      if (typeof v === 'string') return v;
      var o = Object(v), ks = ['url', 'open-url', 'openUrl', 'action-url'];
      for (var i = 0; i < ks.length; i++) if (o[ks[i]] !== undefined) return String(o[ks[i]]);
      return '';
    }
    function post(t, s, b, u) { host('notify', JSON.stringify([argStr(t), argStr(s), argStr(b), optURL(u)])); return undefined; }
    G.$notification = { post: post };
    G.$notify = post;

    var hc = {};
    ['get', 'post', 'put', 'delete', 'head', 'options', 'patch'].forEach(function (m) { hc[m] = httpClient(m.toUpperCase()); });
    G.$httpClient = hc;

    // $httpAPI (Surge): policy groups, outbound mode, profile reload — answered by the bridge.
    G.$httpAPI = function (m, p, b, cb) {
      var d = { m: argStr(m).toUpperCase(), p: argStr(p), cb: -1 };
      if (b !== undefined && b !== null) {
        d.hasB = true;
        if (typeof b === 'string') { d.bs = true; d.b = b; } else { d.b = exportValue(b, 0, []); }
      }
      if (typeof cb === 'function') d.cb = reg(function (x) { cb(x.v); });
      host('api', JSON.stringify(d));
      return undefined;
    };
    G.$task = { fetch: taskFetch };

    // small helpers JavaScriptCore apps / browsers have and bundled scripts expect
    G.TextEncoder = function TextEncoder() {
      this.encoding = 'utf-8';
      this.encode = function (s) { return take(utf8Blob(s === undefined ? '' : s)); };
    };
    G.TextDecoder = function TextDecoder() {
      this.encoding = 'utf-8';
      this.decode = function (x) { var id = toBlob(x); return id < 0 ? '' : blobText(id); };
    };
    G.btoa = function (s) {
      var r = host('btoa', String(s));
      if (r === '!') {
        var ex = new TypeError("Failed to execute 'btoa': The string to be encoded contains characters outside of the Latin1 range.");
        ex.name = 'InvalidCharacterError';
        throw ex;
      }
      return r;
    };
    G.atob = function (s) { return host('atob', String(s)); };

    function geo(kind) { return function (ip) { var r = host('geo', kind + String(ip)); return r === '' ? null : r; }; }
    G.$utils = {
      geoip: geo('c'), ipasn: geo('a'), ipaso: geo('o'),
      ungzip: function (x) {
        var id = toBlob(x);
        if (id < 0) return null;
        var o = +host('ungzip', String(id));
        return o < 0 ? null : take(o);
      }
    };
    // Egern adapter helpers (egernadapter.go)
    G.__egernEnv = S.egernEnv;
    G.__egernCron = S.egernCron;
    G.__egernCompress = function (op, x) {
      var id = toBlob(x);
      if (id < 0) return null;
      var o = +host('compress', String(op) + ',' + id);
      return o < 0 ? null : take(o);
    };
    installURL();

    var gl = S.globals || {};
    for (var gk in gl) G[gk] = gl[gk];

    if (S.req) {
      var q = S.req;
      var ro = { url: q.url, method: q.method, headers: ciHeaders(q.headers), id: q.id };
      if (S.phase === 'request' && q.body >= 0) setBody(ro, q.body, S.binary, q.borrow);
      G.$request = ro;
      if (S.resp) {
        var p = S.resp;
        var so = { status: p.status, statusCode: p.status, headers: ciHeaders(p.headers) };
        if (p.body >= 0) setBody(so, p.body, S.binary, p.borrow);
        G.$response = so;
      }
    }
  }

  define(G, '__tern_begin', function (setup) {
    var S = JSON.parse(setup);
    reset();
    R = { done: false, phase: S.phase, echo: !!S.echo, wantExport: !!S.export, timers: {}, timerID: 0, cbs: {}, cbID: 0,
      origBody: undefined, origBB: undefined, hasOrigBB: false, lazy: null, bodyObj: null, bodyBlob: -1, borrow: false };
    install(S);
  });
  define(G, '__tern_fire', function (id) {
    var t = R && R.timers[id];
    if (!t) return;
    if (!t.repeat) delete R.timers[id];
    t.fn.apply(undefined, t.args);
  });
  define(G, '__tern_deliver', function (json) {
    var d = JSON.parse(json);
    var c = R && R.cbs[d.id];
    if (!c) return;
    delete R.cbs[d.id];
    c(d);
  });

  BASE = Object.create(null);
  var names = Object.getOwnPropertyNames(G);
  for (var i = 0; i < names.length; i++) BASE[names[i]] = true;
})(this);
