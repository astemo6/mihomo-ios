import Foundation

// fix/nc-0.20.2: moved here from PacketTunnel/NativeMitM/Script/NativeTaskRunner.swift (unchanged) so the app's
// 定时任务 form can preview the next run with the same parser the tunnel schedules with. Pure Foundation — no
// tunnel / engine dependencies. 需同步 feat/nc-kernel.
// NCCron: the retired bridge (5 or 6 fields, names, steps, Vixie dom/dow OR), local time.

struct NCCron {
    let expr: String
    private var sec: UInt64 = 0, min: UInt64 = 0, hour: UInt64 = 0, dom: UInt64 = 0, mon: UInt64 = 0, dow: UInt64 = 0
    private var domStar = false, dowStar = false

    private static let monNames = ["jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12]
    private static let dowNames = ["sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6]
    private static let macros = ["@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
                                 "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"]

    init?(_ raw: String) {
        var e = raw.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\"'")).trimmingCharacters(in: .whitespaces)
        if let m = Self.macros[e.lowercased()] { e = m }
        var f = e.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        expr = f.joined(separator: " ")
        if f.count == 5 { f.insert("0", at: 0) } else if f.count != 6 { return nil }
        guard let s = Self.field(f[0], 0, 59, nil), let mi = Self.field(f[1], 0, 59, nil), let h = Self.field(f[2], 0, 23, nil),
              let d = Self.field(f[3], 1, 31, nil), let mo = Self.field(f[4], 1, 12, Self.monNames),
              let w = Self.field(f[5], 0, 6, Self.dowNames) else { return nil }
        (sec, min, hour, dom, mon, dow) = (s.0, mi.0, h.0, d.0, mo.0, w.0)
        (domStar, dowStar) = (d.1, w.1)
    }

    private static func value(_ s: String, _ names: [String: Int]?) -> Int? {
        if let names, let v = names[s.lowercased()] { return v }
        return Int(s)
    }

    private static func field(_ f: String, _ lo: Int, _ hi: Int, _ names: [String: Int]?) -> (UInt64, Bool)? {
        if f == "*" || f == "?" {
            var m: UInt64 = 0
            for i in lo...hi { m |= 1 << UInt64(i) }
            return (m, true)
        }
        var m: UInt64 = 0
        for var part in f.split(separator: ",", omittingEmptySubsequences: false).map(String.init) {
            var step = 1
            if let i = part.firstIndex(of: "/") {
                guard let s = Int(part[part.index(after: i)...]), s > 0 else { return nil }
                // a step past the field's span only ever selects the start; capping it keeps `i += step` from
                // overflowing (and trapping) on a config like "*/9223372036854775807"
                step = Swift.min(s, hi - lo + 1)
                part = String(part[..<i])
            }
            var a = lo, b = hi
            if part != "*" && part != "?" {
                let r = part.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
                guard let va = value(r[0], names) else { return nil }
                a = va; b = va
                if r.count == 2 {
                    guard let vb = value(r[1], names) else { return nil }
                    b = vb
                } else if step > 1 {
                    b = hi
                }
            }
            if names != nil && hi == 6 {
                if a == 7 && b == 7 { a = 0; b = 0 } else if b == 7 { b = 6; m |= 1 }
            }
            guard a >= lo, b <= hi, a <= b else { return nil }
            var i = a
            while i <= b { m |= 1 << UInt64(i); i += step }
        }
        return (m, false)
    }

    private func dayOK(_ c: DateComponents) -> Bool {
        let d = dom & (1 << UInt64(c.day ?? 1)) != 0
        let w = dow & (1 << UInt64((c.weekday ?? 1) - 1)) != 0
        if domStar && dowStar { return true }
        if domStar { return w }
        if dowStar { return d }
        return d || w
    }

    /// First fire time strictly after t (nil if none within 5 years), local calendar.
    func next(after t: Date) -> Date? {
        let cal = Calendar.current
        var cur = Date(timeIntervalSince1970: floor(t.timeIntervalSince1970) + 1)
        let limit = cal.date(byAdding: .year, value: 5, to: cur) ?? cur.addingTimeInterval(5 * 365 * 86400)
        var guardSteps = 0
        while cur < limit && guardSteps < 200_000 {
            guardSteps += 1
            let c = cal.dateComponents([.year, .month, .day, .hour, .minute, .second, .weekday], from: cur)
            func at(_ y: Int, _ mo: Int, _ d: Int, _ h: Int, _ mi: Int) -> Date {
                cal.date(from: DateComponents(year: y, month: mo, day: d, hour: h, minute: mi, second: 0)) ?? cur.addingTimeInterval(60)
            }
            let (y, mo, d, h, mi, s) = (c.year!, c.month!, c.day!, c.hour!, c.minute!, c.second!)
            if mon & (1 << UInt64(mo)) == 0 { cur = at(y, mo + 1, 1, 0, 0); continue }
            if !dayOK(c) { cur = at(y, mo, d + 1, 0, 0); continue }
            if hour & (1 << UInt64(h)) == 0 { cur = at(y, mo, d, h + 1, 0); continue }
            if min & (1 << UInt64(mi)) == 0 { cur = at(y, mo, d, h, mi + 1); continue }
            if sec & (1 << UInt64(s)) == 0 { cur = cur.addingTimeInterval(1); continue }
            return cur
        }
        return nil
    }
}
