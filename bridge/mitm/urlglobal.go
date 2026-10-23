package mitm

// URL / URLSearchParams for scripts (v0.19.22). Surge, Loon, Quantumult X and Egern scripts call
// `new URL($request.url)` and `url.searchParams.set(…)` without bundling a polyfill (NSRingo
// GeoServices / WeatherKit, many Egern-era scripts); goja has neither, so those scripts died with
// 「ReferenceError: URL is not defined」. Both globals are installed lazily: the first read of `URL` or
// `URLSearchParams` runs a small WHATWG-style implementation (compiled once per process) in that runtime,
// so scripts that never touch them pay nothing.

import (
	"sync"

	"github.com/dop251/goja"
)

var (
	urlProgOnce sync.Once
	urlProg     *goja.Program
	urlProgErr  error
)

func urlProgram() (*goja.Program, error) {
	urlProgOnce.Do(func() { urlProg, urlProgErr = goja.Compile("url-polyfill.js", urlPolyfillJS, true) })
	return urlProg, urlProgErr
}

// installURLGlobals defines lazy URL / URLSearchParams on the global object.
func installURLGlobals(rt *goja.Runtime) {
	g := rt.GlobalObject()
	var loaded goja.Value // the polyfill's {URL, URLSearchParams}
	load := func() *goja.Object {
		if loaded == nil {
			p, err := urlProgram()
			if err != nil {
				panic(rt.NewGoError(err))
			}
			v, err := rt.RunProgram(p)
			if err != nil {
				panic(err)
			}
			loaded = v
		}
		return loaded.ToObject(rt)
	}
	for _, name := range []string{"URL", "URLSearchParams"} {
		n := name
		getter := rt.ToValue(func(goja.FunctionCall) goja.Value {
			v := load().Get(n)
			// replace the accessor by the value (scripts may also overwrite it with their own polyfill)
			_ = g.DefineDataProperty(n, v, goja.FLAG_TRUE, goja.FLAG_FALSE, goja.FLAG_TRUE)
			return v
		})
		setter := rt.ToValue(func(call goja.FunctionCall) goja.Value {
			_ = g.DefineDataProperty(n, call.Argument(0), goja.FLAG_TRUE, goja.FLAG_FALSE, goja.FLAG_TRUE)
			return goja.Undefined()
		})
		_ = g.DefineAccessorProperty(n, getter, setter, goja.FLAG_TRUE, goja.FLAG_FALSE)
	}
}

const urlPolyfillJS = `(function () {
"use strict";
var special = { "http:": "80", "https:": "443", "ws:": "80", "wss:": "443", "ftp:": "21", "file:": "" };
function enc(s) {
  return encodeURIComponent(s).replace(/[!'()~]/g, function (c) { return "%" + c.charCodeAt(0).toString(16).toUpperCase(); }).replace(/%20/g, "+");
}
function dec(s) {
  s = s.replace(/\+/g, " ");
  try { return decodeURIComponent(s); } catch (e) {
    return s.replace(/(%[0-9A-Fa-f]{2})+/g, function (m) { try { return decodeURIComponent(m); } catch (e2) { return m; } });
  }
}
function USP(init) {
  if (!(this instanceof USP)) throw new TypeError("Failed to construct 'URLSearchParams': Please use the 'new' operator.");
  Object.defineProperty(this, "_l", { value: [], writable: true });
  Object.defineProperty(this, "_u", { value: null, writable: true });
  if (init === undefined || init === null) return;
  if (init instanceof USP) { this._l = init._l.map(function (p) { return [p[0], p[1]]; }); return; }
  if (typeof init === "object") {
    if (typeof init[Symbol.iterator] === "function") {
      var it = init[Symbol.iterator](), r;
      while (!(r = it.next()).done) {
        var pair = Array.from(r.value);
        if (pair.length !== 2) throw new TypeError("Each query pair must be an iterable [name, value] tuple");
        this._l.push([String(pair[0]), String(pair[1])]);
      }
    } else {
      for (var k in init) if (Object.prototype.hasOwnProperty.call(init, k)) this._l.push([k, String(init[k])]);
    }
    return;
  }
  this._parse(String(init));
}
USP.prototype._parse = function (s) {
  this._l = [];
  if (s.charAt(0) === "?") s = s.slice(1);
  var parts = s.split("&");
  for (var i = 0; i < parts.length; i++) {
    if (!parts[i]) continue;
    var j = parts[i].indexOf("=");
    if (j < 0) this._l.push([dec(parts[i]), ""]);
    else this._l.push([dec(parts[i].slice(0, j)), dec(parts[i].slice(j + 1))]);
  }
};
USP.prototype._upd = function () { if (this._u) { var q = this.toString(); this._u._q = q ? "?" + q : ""; } };
USP.prototype.append = function (k, v) { this._l.push([String(k), String(v)]); this._upd(); };
USP.prototype["delete"] = function (k, v) {
  k = String(k);
  this._l = this._l.filter(function (p) { return !(p[0] === k && (v === undefined || p[1] === String(v))); });
  this._upd();
};
USP.prototype.get = function (k) { k = String(k); for (var i = 0; i < this._l.length; i++) if (this._l[i][0] === k) return this._l[i][1]; return null; };
USP.prototype.getAll = function (k) { k = String(k); return this._l.filter(function (p) { return p[0] === k; }).map(function (p) { return p[1]; }); };
USP.prototype.has = function (k, v) { k = String(k); return this._l.some(function (p) { return p[0] === k && (v === undefined || p[1] === String(v)); }); };
USP.prototype.set = function (k, v) {
  k = String(k); v = String(v);
  var out = [], done = false;
  for (var i = 0; i < this._l.length; i++) {
    if (this._l[i][0] === k) { if (!done) { out.push([k, v]); done = true; } } else out.push(this._l[i]);
  }
  if (!done) out.push([k, v]);
  this._l = out; this._upd();
};
USP.prototype.sort = function () {
  var l = this._l.map(function (p, i) { return [p, i]; });
  l.sort(function (a, b) { return a[0][0] < b[0][0] ? -1 : a[0][0] > b[0][0] ? 1 : a[1] - b[1]; });
  this._l = l.map(function (x) { return x[0]; }); this._upd();
};
USP.prototype.forEach = function (cb, self) { var l = this._l.slice(); for (var i = 0; i < l.length; i++) cb.call(self, l[i][1], l[i][0], this); };
USP.prototype.toString = function () { return this._l.map(function (p) { return enc(p[0]) + "=" + enc(p[1]); }).join("&"); };
USP.prototype.entries = function () { return this._l.map(function (p) { return [p[0], p[1]]; })[Symbol.iterator](); };
USP.prototype.keys = function () { return this._l.map(function (p) { return p[0]; })[Symbol.iterator](); };
USP.prototype.values = function () { return this._l.map(function (p) { return p[1]; })[Symbol.iterator](); };
USP.prototype[Symbol.iterator] = USP.prototype.entries;
Object.defineProperty(USP.prototype, "size", { get: function () { return this._l.length; } });
Object.defineProperty(USP.prototype, Symbol.toStringTag, { value: "URLSearchParams" });

var re = /^([a-zA-Z][a-zA-Z0-9+.\-]*:)(?:\/\/(?:([^:@\/?#]*)(?::([^@\/?#]*))?@)?(\[[^\]]*\]|[^:\/?#]*)(?::(\d*))?)?([^?#]*)(\?[^#]*)?(#.*)?$/;
function removeDots(p) {
  var out = [], segs = p.split("/");
  for (var i = 0; i < segs.length; i++) {
    var s = segs[i];
    if (s === "..") { if (out.length > 1) out.pop(); if (i === segs.length - 1) out.push(""); }
    else if (s === ".") { if (i === segs.length - 1) out.push(""); }
    else out.push(s);
  }
  return out.join("/");
}
function resolve(input, base) {
  if (/^[a-zA-Z][a-zA-Z0-9+.\-]*:/.test(input)) return input;
  var b = new URLImpl(base);
  if (input.slice(0, 2) === "//") return b.protocol + input;
  var auth = b.protocol + "//" + (b.username ? b.username + (b.password ? ":" + b.password : "") + "@" : "") + b.host;
  if (input === "") return auth + b.pathname + b.search;
  if (input.charAt(0) === "#") return auth + b.pathname + b.search + input;
  if (input.charAt(0) === "?") return auth + b.pathname + input;
  var path, rest = input.match(/^([^?#]*)(.*)$/);
  if (rest[1].charAt(0) === "/") path = rest[1];
  else path = b.pathname.slice(0, b.pathname.lastIndexOf("/") + 1) + rest[1];
  return auth + removeDots(path) + rest[2];
}
function URLImpl(url, base) {
  if (!(this instanceof URLImpl)) throw new TypeError("Failed to construct 'URL': Please use the 'new' operator.");
  url = String(url).trim();
  if (base !== undefined) url = resolve(url, String(base instanceof URLImpl ? base.href : base));
  var m = re.exec(url);
  if (!m) throw new TypeError("Failed to construct 'URL': Invalid URL");
  var proto = m[1].toLowerCase();
  var hasAuthority = url.slice(m[1].length, m[1].length + 2) === "//";
  if (special[proto] !== undefined && proto !== "file:" && (!hasAuthority || !m[4])) throw new TypeError("Failed to construct 'URL': Invalid URL");
  Object.defineProperty(this, "_p", { value: proto, writable: true });
  Object.defineProperty(this, "_a", { value: hasAuthority, writable: true });
  Object.defineProperty(this, "_user", { value: m[2] || "", writable: true });
  Object.defineProperty(this, "_pass", { value: m[3] || "", writable: true });
  Object.defineProperty(this, "_h", { value: (m[4] || "").toLowerCase(), writable: true });
  var port = m[5] || "";
  if (port === special[proto]) port = "";
  Object.defineProperty(this, "_port", { value: port, writable: true });
  var path = m[6] || "";
  if (special[proto] !== undefined) { path = path.replace(/\\/g, "/"); if (path === "" || path.charAt(0) !== "/") path = "/" + path; path = removeDots(path); }
  Object.defineProperty(this, "_path", { value: path.replace(/ /g, "%20"), writable: true });
  Object.defineProperty(this, "_q", { value: m[7] && m[7] !== "?" ? m[7].replace(/ /g, "%20") : "", writable: true });
  Object.defineProperty(this, "_hash", { value: m[8] && m[8] !== "#" ? m[8] : "", writable: true });
  var sp = new USP(this._q);
  sp._u = this;
  Object.defineProperty(this, "_sp", { value: sp, writable: true });
}
function acc(name, get, set) { Object.defineProperty(URLImpl.prototype, name, { get: get, set: set, enumerable: true, configurable: true }); }
acc("protocol", function () { return this._p; }, function (v) { v = String(v); if (v.slice(-1) !== ":") v += ":"; this._p = v.toLowerCase(); });
acc("username", function () { return this._user; }, function (v) { this._user = String(v); });
acc("password", function () { return this._pass; }, function (v) { this._pass = String(v); });
acc("hostname", function () { return this._h; }, function (v) { this._h = String(v).toLowerCase(); });
acc("port", function () { return this._port; }, function (v) { v = String(v); this._port = v === special[this._p] ? "" : v; });
acc("host", function () { return this._h + (this._port ? ":" + this._port : ""); }, function (v) {
  var m = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(String(v)); if (!m) return;
  this._h = m[1].toLowerCase(); if (m[2] !== undefined) this.port = m[2];
});
acc("origin", function () { return special[this._p] !== undefined && this._p !== "file:" ? this._p + "//" + this.host : "null"; });
acc("pathname", function () { return this._path; }, function (v) { v = String(v); if (special[this._p] !== undefined && v.charAt(0) !== "/") v = "/" + v; this._path = v; });
acc("search", function () { return this._q; }, function (v) {
  v = String(v); if (v && v.charAt(0) !== "?") v = "?" + v; this._q = v === "?" ? "" : v; this._sp._parse(this._q);
});
acc("searchParams", function () { return this._sp; });
acc("hash", function () { return this._hash; }, function (v) { v = String(v); if (v && v.charAt(0) !== "#") v = "#" + v; this._hash = v === "#" ? "" : v; });
acc("href", function () {
  var auth = this._a ? "//" + (this._user ? this._user + (this._pass ? ":" + this._pass : "") + "@" : "") + this.host : "";
  return this._p + auth + this._path + this._q + this._hash;
}, function (v) { var u = new URLImpl(v); for (var k in { _p: 1, _a: 1, _user: 1, _pass: 1, _h: 1, _port: 1, _path: 1, _q: 1, _hash: 1 }) this[k] = u[k]; this._sp._parse(this._q); });
URLImpl.prototype.toString = function () { return this.href; };
URLImpl.prototype.toJSON = function () { return this.href; };
Object.defineProperty(URLImpl.prototype, Symbol.toStringTag, { value: "URL" });
URLImpl.canParse = function (u, b) { try { new URLImpl(u, b); return true; } catch (e) { return false; } };
URLImpl.parse = function (u, b) { try { return new URLImpl(u, b); } catch (e) { return null; } };
Object.defineProperty(URLImpl, "name", { value: "URL" });
Object.defineProperty(USP, "name", { value: "URLSearchParams" });
return { URL: URLImpl, URLSearchParams: USP };
})()`
