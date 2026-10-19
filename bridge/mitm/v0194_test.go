package mitm

import (
	"strings"
	"testing"
)

// v0.19.4 (review 5): Egern native-script adapter semantics, exercised through the 脚本调试 runner.
func v0194Run(t *testing.T, typ, code string) DebugOutput {
	t.Helper()
	in := DebugInput{Code: code, Type: typ,
		Request:  &DebugHTTP{URL: "https://a.test/p", Method: "POST", Headers: map[string]string{"Host": "a.test", "Content-Type": "text/plain"}, Body: "orig"},
		Response: &DebugHTTP{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"ad":true}`}}
	return DebugRun(t.TempDir(), in, nil)
}

func TestV0194EgernArrowExportsRun(t *testing.T) {
	for _, code := range []string{
		"export default async (ctx) => ({ url: ctx.request.url + '?x=1' })",
		"export default ctx => { return { url: ctx.request.url + '?x=1' } }",
		"  export default async function main(ctx) { return { url: ctx.request.url + '?x=1' } }",
	} {
		out := v0194Run(t, "http-request", code)
		if !out.OK || out.Result == nil || out.Result.URL != "https://a.test/p?x=1" {
			t.Errorf("%q: ok=%v err=%q result=%+v", code, out.OK, out.Error, out.Result)
		}
	}
	if !IsEgernNative("export default (ctx) => 1") || IsEgernNative("// export default\n$done({})") {
		t.Error("IsEgernNative detection")
	}
}

func TestV0194EgernSemantics(t *testing.T) {
	// headers proxy: set / delete by any case, status, JSON body
	out := v0194Run(t, "http-response", `export default async function(ctx){
	  const j = await ctx.response.json(); j.ad = false;
	  const h = ctx.response.headers; h['X-C'] = '3'; delete h['content-type'];
	  return { status: 201, headers: h, body: j } }`)
	if !out.OK || out.Result.Status != 201 || out.Result.Body != `{"ad":false}` || out.Result.Headers["X-C"] != "3" || out.Result.Headers["Content-Type"] != "" {
		t.Errorf("response edit: %+v err=%q", out.Result, out.Error)
	}
	// ctx.respond in a response script replaces the response (was ignored before v0.19.4)
	out = v0194Run(t, "http-response", `export default async function(ctx){ return ctx.respond({ status: 403, headers: {'X-R':'1'}, body: 'no' }) }`)
	if !out.OK || out.Result.Status != 403 || out.Result.Body != "no" {
		t.Errorf("respond in response phase: %+v %s", out.Result, out.DoneJSON)
	}
	// request phase: respond → local answer, abort, returning ctx.request keeps the body
	out = v0194Run(t, "http-request", `export default async function(ctx){ return ctx.respond({ status: 204 }) }`)
	if out.Mock == nil || out.Mock.Status != 204 {
		t.Errorf("respond in request phase: %+v", out.Mock)
	}
	out = v0194Run(t, "http-request", `export default async function(ctx){ ctx.request.headers.set('X-B','2'); return ctx.request }`)
	if !out.OK || out.Result.Headers["X-B"] != "2" || out.Result.Body != "orig" {
		t.Errorf("return ctx.request: %+v", out.Result)
	}
	// an exception passes the request through unchanged and is logged
	out = v0194Run(t, "http-request", `export default async function(ctx){ throw new Error('boom') }`)
	if !out.OK || out.Result.URL != "https://a.test/p" || len(out.Logs) == 0 || !strings.Contains(out.Logs[0].Msg, "boom") {
		t.Errorf("exception: %+v logs=%+v", out.Result, out.Logs)
	}
	// storage delete, compress round trip, lookupIP without databases, widget → panel
	out = v0194Run(t, "generic", `export default async function(ctx){
	  ctx.storage.set('k','v'); ctx.storage.delete('k');
	  const u = await ctx.compress.gunzip(await ctx.compress.gzip('hello'));
	  const b = await ctx.compress.unbrotli(await ctx.compress.brotli('br'));
	  return { type: 'widget', children: [{ text: String(ctx.storage.get('k')) }, { text: new TextDecoder().decode(u) + new TextDecoder().decode(b) }, { text: String(ctx.lookupIP('1.1.1.1')) }] } }`)
	if !out.OK || !strings.Contains(out.DoneJSON, `"title": "null"`) || !strings.Contains(out.DoneJSON, `hellobr\nnull`) {
		t.Errorf("generic: %s err=%q", out.DoneJSON, out.Error)
	}
	// $utils on bad input returns null instead of throwing
	out = v0194Run(t, "generic", `$done({ title: String($utils.ungzip('notgzip')) + String($utils.geoip('')) + String($utils.ipasn('x')) })`)
	if !strings.Contains(out.DoneJSON, `"title": "nullnullnull"`) {
		t.Errorf("$utils: %s", out.DoneJSON)
	}
}
