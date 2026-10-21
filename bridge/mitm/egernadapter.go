package mitm

// Egern native scripts (`export default async function(ctx) { … }`) run through a thin adapter: the
// module export becomes a local function and a small JS prelude builds `ctx` from the Surge-compatible
// globals this runtime already has ($request / $response / $httpClient / $persistentStore /
// $notification / $utils), then maps the function's return value onto $done. One script engine, one
// internal model — Egern is only translated at the edge. Not provided: ctx.ssh, Blob / FormData and
// ReadableStream bodies (body is the text or Uint8Array), the widget DSL beyond text (generic scripts
// become panels: first text = title, other texts = content).

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"io"
	"regexp"

	"github.com/andybalholm/brotli"
	"github.com/dop251/goja"
)

var (
	egernExportRe = regexp.MustCompile(`(?m)^[ \t]*export[ \t]+default[ \t]+`)
	egernImportRe = regexp.MustCompile(`(?m)^[ \t]*(import[ \t{*'"]|export[ \t]+(const|let|var|function|class|\{))`)
)

// IsEgernNative reports whether a script uses Egern's native module shape.
func IsEgernNative(code string) bool { return egernNativeRe.MatchString(code) }

// adaptEgern rewrites a native Egern script into a plain script that calls $done.
func adaptEgern(code string) (string, error) {
	if egernImportRe.MatchString(code) {
		return "", errors.New("Egern 脚本使用了 import 或多个 export，只支持单文件 export default 函数")
	}
	loc := egernExportRe.FindStringIndex(code)
	if loc == nil {
		return "", errors.New("没有找到 export default")
	}
	return code[:loc[0]] + "var __egernMain = " + code[loc[1]:] + "\n;\n" + egernPrelude, nil
}

// installEgern adds the Go helpers the prelude needs (env, cron, compression).
func (rc *runCtx) installEgern(set func(string, any)) {
	rt := rc.rt
	env := rt.NewObject()
	for k, v := range rc.script.Env {
		_ = env.Set(k, v)
	}
	set("__egernEnv", env)
	set("__egernCron", rc.script.Cron)
	set("__egernCompress", func(call goja.FunctionCall) goja.Value {
		in, ok := rc.bodyBytes(call.Argument(1))
		if !ok {
			return goja.Null()
		}
		out, err := egernCompress(call.Argument(0).String(), in)
		if err != nil {
			return goja.Null()
		}
		return rc.uint8Array(out)
	})
}

func egernCompress(op string, in []byte) ([]byte, error) {
	var buf bytes.Buffer
	readAll := func(r io.Reader) ([]byte, error) { return readAllLimited(r, MaxBody) }
	switch op {
	case "gzip":
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(in)
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
		_, _ = w.Write(in)
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "brotli":
		w := brotli.NewWriter(&buf)
		_, _ = w.Write(in)
		if err := w.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "gunzip", "inflate":
		return inflateAny(in)
	case "unbrotli":
		return readAll(brotli.NewReader(bytes.NewReader(in)))
	}
	return nil, errors.New("unknown op")
}

// egernPrelude runs after the script body inside the same function scope.
const egernPrelude = `(function () {
  var hasReq = typeof $request !== 'undefined' && $request;
  var hasResp = typeof $response !== 'undefined' && $response;
  function lc(k) { return String(k).toLowerCase(); }
  var TO_OBJECT = typeof Symbol === 'function' ? Symbol('toObject') : '__egernToObject';
  function makeHeaders(src) {
    var map = {};
    function put(k, v) {
      var e = map[lc(k)];
      if (!e) { e = map[lc(k)] = { name: String(k), values: [] }; }
      e.values.push(String(v));
    }
    if (src) {
      var keys = Object.keys(src);
      for (var i = 0; i < keys.length; i++) {
        var v = src[keys[i]];
        if (v === undefined || v === null) continue;
        if (Array.isArray(v)) { for (var j = 0; j < v.length; j++) put(keys[i], v[j]); } else put(keys[i], v);
      }
    }
    var api = {
      get: function (n) { var e = map[lc(n)]; return e ? e.values.join(', ') : null; },
      getAll: function (n) { var e = map[lc(n)]; return e ? e.values.slice() : []; },
      has: function (n) { return !!map[lc(n)]; },
      set: function (n, v) { map[lc(n)] = { name: String(n), values: [String(v)] }; },
      append: function (n, v) { put(n, v); },
      delete: function (n) { delete map[lc(n)]; },
      forEach: function (fn) { for (var k in map) fn(map[k].values.join(', '), map[k].name); },
      toObject: function () {
        var o = {};
        for (var k in map) { var e = map[k]; o[e.name] = e.values.length > 1 ? e.values.slice() : e.values[0]; }
        return o;
      }
    };
    // r7 B30: a header named like a method (get / set / has / append / delete / forEach / toObject) is
    // what property access returns; the methods are what is left when no such header exists. The adapter
    // itself reaches toObject through a symbol, so such a header never breaks the conversion back.
    api[TO_OBJECT] = api.toObject;
    return new Proxy(api, {
      get: function (t, p) {
        if (typeof p !== 'string') return t[p];
        var e = map[lc(p)];
        if (e) return e.values.length > 1 ? e.values.slice() : e.values[0];
        return p in t ? t[p] : undefined;
      },
      set: function (t, p, v) { api.set(p, v); return true; },
      deleteProperty: function (t, p) { api.delete(p); return true; },
      has: function (t, p) { return (p in t) || !!map[lc(p)]; },
      ownKeys: function () { return Object.keys(map).map(function (k) { return map[k].name; }); },
      getOwnPropertyDescriptor: function (t, p) {
        var e = map[lc(p)];
        if (!e) return undefined;
        return { value: e.values.length > 1 ? e.values.slice() : e.values[0], enumerable: true, configurable: true, writable: true };
      }
    });
  }
  function toBytes(b) {
    if (b === undefined || b === null) return new Uint8Array(0);
    if (typeof b === 'string') return new TextEncoder().encode(b);
    if (b instanceof ArrayBuffer) return new Uint8Array(b);
    return b;
  }
  function withBody(target, raw) {
    target.body = raw === undefined ? null : raw;
    target.text = function () {
      if (raw === undefined || raw === null) return Promise.resolve('');
      if (typeof raw === 'string') return Promise.resolve(raw);
      return Promise.resolve(new TextDecoder().decode(toBytes(raw)));
    };
    target.json = function () { return target.text().then(function (t) { return JSON.parse(t); }); };
    target.arrayBuffer = function () { var u = toBytes(raw); return Promise.resolve(u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength)); };
    target.bytes = function () { return Promise.resolve(toBytes(raw)); };
    return target;
  }
  function plainHeaders(h) {
    if (!h) return undefined;
    if (typeof h[TO_OBJECT] === 'function') return h[TO_OBJECT]();
    if (typeof h.toObject === 'function') return h.toObject();
    return h;
  }
  function bodyOut(b) {
    if (b === undefined || b === null) return undefined;
    if (typeof b === 'string' || b instanceof Uint8Array || b instanceof ArrayBuffer) return b;
    return JSON.stringify(b);
  }
  function http(method) {
    return function (url, opts) {
      opts = opts || {};
      return new Promise(function (resolve, reject) {
        var req = { url: url, headers: plainHeaders(opts.headers) || {}, 'binary-mode': true };
        var b = opts.body;
        if (b !== undefined && b !== null) {
          if (typeof b === 'object' && !(b instanceof Uint8Array) && !(b instanceof ArrayBuffer)) {
            b = JSON.stringify(b);
            var ct = false;
            for (var k in req.headers) if (lc(k) === 'content-type') ct = true;
            if (!ct) req.headers['Content-Type'] = 'application/json';
          }
          req.body = b;
        }
        if (opts.timeout) req.timeout = opts.timeout / 1000;
        if (opts.policy) req.policy = opts.policy;
        if (opts.redirect === 'manual' || opts.redirect === 'error') req['auto-redirect'] = false;
        if (opts.insecureTls) req.insecure = true;
        $httpClient[method](req, function (err, resp, data) {
          if (err) { reject(new Error(String(err))); return; }
          var status = resp ? (resp.status || resp.statusCode) : 0;
          if (opts.redirect === 'error' && status >= 300 && status < 400) { reject(new Error('redirect')); return; }
          resolve(withBody({ status: status, headers: makeHeaders(resp ? resp.headers : {}) }, data));
        });
      });
    };
  }
  var device = { cellular: { carrier: null, radio: null }, wifi: { ssid: null, bssid: null },
    ipv4: { address: null, gateway: null, interface: null }, ipv6: { address: null, interface: null }, dnsServers: [] };
  if (typeof $network !== 'undefined' && $network) {
    var v4 = $network.v4 || {}, v6 = $network.v6 || {};
    device.ipv4 = { address: v4.primaryAddress || null, gateway: v4.primaryRouter || null, interface: v4.primaryInterface || null };
    device.ipv6 = { address: v6.primaryAddress || null, interface: v6.primaryInterface || null };
    device.dnsServers = $network.dns || [];
  }
  var ctx = {
    script: { name: (typeof $script !== 'undefined' && $script) ? $script.name : '' },
    env: __egernEnv,
    app: { version: '0.6', language: 'zh-Hans' },
    device: device,
    cron: __egernCron || undefined,
    http: {
      get: http('get'), post: http('post'), put: http('put'), delete: http('delete'),
      head: http('head'), options: http('options'), patch: http('patch')
    },
    storage: {
      get: function (k) { var v = $persistentStore.read(k); return v === undefined ? null : v; },
      set: function (k, v) { $persistentStore.write(String(v), k); },
      getJSON: function (k) { var v = $persistentStore.read(k); if (v === undefined || v === null || v === '') return null; try { return JSON.parse(v); } catch (e) { return null; } },
      setJSON: function (k, v) { $persistentStore.write(JSON.stringify(v), k); },
      delete: function (k) { $persistentStore.write(null, k); }
    },
    notify: function (o) {
      o = o || {};
      var opts;
      if (o.action && o.action.type === 'openUrl') opts = { url: o.action.url };
      $notification.post(o.title || '', o.subtitle || '', o.body || '', opts);
    },
    lookupIP: function (ip) {
      var c = $utils.geoip(ip), a = $utils.ipasn(ip), org = $utils.ipaso(ip);
      if (!c && !a && !org) return null;
      return { country: c || '', asn: a ? Number(a) : 0, organization: org || '' };
    },
    compress: {
      gzip: function (d) { return Promise.resolve(__egernCompress('gzip', d)); },
      gunzip: function (d) { return Promise.resolve(__egernCompress('gunzip', d)); },
      deflate: function (d) { return Promise.resolve(__egernCompress('deflate', d)); },
      inflate: function (d) { return Promise.resolve(__egernCompress('inflate', d)); },
      brotli: function (d) { return Promise.resolve(__egernCompress('brotli', d)); },
      unbrotli: function (d) { return Promise.resolve(__egernCompress('unbrotli', d)); }
    },
    ssh: { connect: function () { return Promise.reject(new Error('ctx.ssh 不支持')); } },
    respond: function (r) { return { __egernRespond: r || {} }; },
    abort: function () { return { __egernAbort: true }; }
  };
  if (hasReq) {
    ctx.request = withBody({ method: $request.method, url: $request.url, headers: makeHeaders($request.headers) }, hasResp ? undefined : $request.body);
  }
  if (hasResp) {
    ctx.response = withBody({ status: $response.status, headers: makeHeaders($response.headers) }, $response.body);
  }
  function texts(node, out) {
    if (!node || typeof node !== 'object') return out;
    if (typeof node.text === 'string' && node.text !== '') out.push(node.text);
    var ch = node.children || [];
    for (var i = 0; i < ch.length; i++) texts(ch[i], out);
    return out;
  }
  function finish(ret) {
    if (ret && ret.__egernAbort) { $done({ __egernAbort: true }); return; }
    if (hasReq && !hasResp) {
      if (ret && ret.__egernRespond) {
        var r = ret.__egernRespond;
        $done({ response: { status: r.status || 200, headers: plainHeaders(r.headers) || {}, body: bodyOut(r.body) } });
        return;
      }
      if (!ret) { $done({}); return; }
      var o = {};
      if (ret.url) o.url = ret.url;
      if (ret.method) o.method = ret.method;
      if (ret.headers) o.headers = plainHeaders(ret.headers);
      if (ret.body !== undefined) o.body = bodyOut(ret.body);
      $done(o);
      return;
    }
    if (hasResp) {
      if (!ret) { $done({}); return; }
      // v0.19.4: ctx.respond() in a response script replaces the response (was ignored).
      if (ret.__egernRespond) {
        var rr = ret.__egernRespond, q = { status: rr.status || 200 };
        if (rr.headers) q.headers = plainHeaders(rr.headers);
        q.body = rr.body === undefined || rr.body === null ? '' : bodyOut(rr.body);
        $done(q);
        return;
      }
      var p = {};
      if (ret.status) p.status = ret.status;
      if (ret.headers) p.headers = plainHeaders(ret.headers);
      if (ret.body !== undefined) p.body = bodyOut(ret.body);
      $done(p);
      return;
    }
    // generic (panel): widget DSL -> title / content; schedule / network: nothing
    if (ret && ret.type === 'widget') {
      var t = texts(ret, []);
      var pn = { title: t[0] || '', content: t.slice(1).join('\n') };
      if (ret.backgroundColor) pn.backgroundColor = ret.backgroundColor;
      $done(pn);
      return;
    }
    $done(ret && typeof ret === 'object' ? ret : {});
  }
  var run;
  try { run = Promise.resolve(__egernMain(ctx)); } catch (e) { run = Promise.reject(e); }
  run.then(finish, function (e) {
    console.error('Egern 脚本异常：' + (e && e.stack ? e.stack : String(e)));
    $done({});
  });
})();
`
