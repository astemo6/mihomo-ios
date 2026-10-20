package mitm

// 脚本调试 (script workbench): run one script against a sample or a captured request / response in a
// throw-away engine and report console output, the $done result, timing and errors. The run uses the
// same ScriptRunner as live traffic (fresh goja runtime, same globals, Egern ctx adapter), so what works
// here works in the tunnel. Differences, by design: console / notifications are captured instead of going
// to the log ring and the notification history; $httpClient dials with the caller's DialFunc (the app
// process dials directly, i.e. through the VPN when it is connected). $persistentStore is the real store.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// DebugHTTP is a sample request or response for a debug run.
type DebugHTTP struct {
	URL     string            `json:"url,omitempty"`
	Method  string            `json:"method,omitempty"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	// BodyBase64 marks Body as base64 (binary bodies, binary-body-mode scripts).
	BodyBase64 bool `json:"bodyBase64,omitempty"`
}

// DebugInput describes one debug run.
type DebugInput struct {
	Code     string     `json:"code"`           // inline source; "" = load Path
	Path     string     `json:"path,omitempty"` // local script name or URL (cached copy is used)
	Name     string     `json:"name,omitempty"`
	Type     string     `json:"type"` // http-request / http-response / generic / cron
	Argument *string    `json:"argument,omitempty"`
	Timeout  int        `json:"timeout,omitempty"` // seconds (default 10, max 60)
	Binary   bool       `json:"binary,omitempty"`  // binary-body-mode
	Request  *DebugHTTP `json:"request,omitempty"`
	Response *DebugHTTP `json:"response,omitempty"`
}

// DebugLog is one console line (t = ms since start).
type DebugLog struct {
	T     int64  `json:"t"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// DebugOutput is the run report.
type DebugOutput struct {
	OK            bool                `json:"ok"`
	Error         string              `json:"error,omitempty"`
	DurationMs    int64               `json:"durationMs"`
	Done          bool                `json:"done"`               // $done was called
	DoneJSON      string              `json:"doneJSON,omitempty"` // the raw $done argument, pretty JSON (bodies clipped)
	Summary       []string            `json:"summary"`            // what the engine would do, in words
	Result        *DebugHTTP          `json:"result,omitempty"`   // the request / response after the script
	Mock          *DebugHTTP          `json:"mock,omitempty"`     // request phase: local answer
	Logs          []DebugLog          `json:"logs"`
	Notifications []map[string]string `json:"notifications"`
}

const debugMaxLogs = 400

func headerFrom(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

func headerMap(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	m := map[string]string{}
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

func (d *DebugHTTP) bytes() []byte {
	if d.BodyBase64 {
		if b, err := decodeB64(d.Body); err == nil {
			return b
		}
	}
	return []byte(d.Body)
}

func bodyOut(b []byte) (string, bool) {
	if utf8.Valid(b) {
		return string(b), false
	}
	return base64Std(b), true
}

// DebugRun executes one script. dial is used for $httpClient / $task.fetch (nil = direct dialer).
func DebugRun(home string, in DebugInput, dial DialFunc) (out DebugOutput) {
	out.Logs, out.Notifications, out.Summary = []DebugLog{}, []map[string]string{}, []string{}
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			out.OK, out.Error = false, fmt.Sprintf("内部错误：%v", p)
		}
		out.DurationMs = time.Since(start).Milliseconds()
	}()
	typ := normScriptType(in.Type)
	if typ == "" {
		typ = "http-response"
	}
	if strings.TrimSpace(in.Code) == "" && in.Path == "" {
		out.Error = "没有脚本内容"
		return
	}
	if dial == nil {
		dial = directDial
	}
	e := New(home, dial, func(string, string) {})
	defer func() { _ = e.Store.Flush() }() // v0.19.9: store writes are coalesced; the run's writes land now
	name := in.Name
	if name == "" {
		name = "调试"
	}
	sc := &Script{Name: name, Type: typ, Path: in.Path, Timeout: in.Timeout, BinaryBody: in.Binary, RequiresBody: true}
	if sc.Timeout <= 0 {
		sc.Timeout = 10
	}
	if sc.Timeout > 60 {
		sc.Timeout = 60
	}
	if in.Argument != nil {
		sc.Argument, sc.HasArgument = *in.Argument, true
	}
	if strings.TrimSpace(in.Code) != "" {
		sc.Source = []byte(in.Code)
	}
	var mu sync.Mutex
	setup := func(rc *runCtx) {
		rc.onLog = func(level, msg string) {
			mu.Lock()
			defer mu.Unlock()
			if len(out.Logs) >= debugMaxLogs {
				if len(out.Logs) == debugMaxLogs {
					out.Logs = append(out.Logs, DebugLog{T: time.Since(start).Milliseconds(), Level: "warn", Msg: "（日志过多，后续输出已省略）"})
				}
				return
			}
			out.Logs = append(out.Logs, DebugLog{T: time.Since(start).Milliseconds(), Level: level, Msg: clip(msg, 4000)})
		}
		rc.onNotify = func(title, sub, body, url string) {
			mu.Lock()
			defer mu.Unlock()
			out.Notifications = append(out.Notifications, map[string]string{"title": title, "subtitle": sub, "body": body, "url": url})
		}
		if typ != "http-request" && typ != "http-response" {
			_ = rc.rt.Set("$network", map[string]any{"v4": map[string]any{}, "wifi": map[string]any{}})
		}
	}

	var req, resp *ScriptHTTP
	isHTTP := typ == "http-request" || typ == "http-response"
	if isHTTP {
		r := in.Request
		if r == nil {
			r = &DebugHTTP{}
		}
		if r.URL == "" {
			r.URL = "https://example.com/"
		}
		if r.Method == "" {
			r.Method = "GET"
		}
		req = &ScriptHTTP{URL: r.URL, Method: strings.ToUpper(r.Method), Header: headerFrom(r.Headers)}
		if b := r.bytes(); len(b) > 0 || typ == "http-request" {
			req.Body, req.HasBody = b, true
		}
		if typ == "http-response" {
			rs := in.Response
			if rs == nil {
				rs = &DebugHTTP{Status: 200}
			}
			if rs.Status == 0 {
				rs.Status = 200
			}
			resp = &ScriptHTTP{Status: rs.Status, Header: headerFrom(rs.Headers), Body: rs.bytes(), HasBody: true}
		}
	}

	runner := e.scripts
	rc, err := runner.execute(sc, req, resp, make(chan struct{}, 1), 60*time.Second, 10*time.Second, setup)
	if err != nil {
		out.Error = err.Error()
		return
	}
	out.OK = true
	if rc == nil || !rc.done {
		out.Summary = append(out.Summary, "脚本结束但没有调用 $done()：线上会在超时后按原样放行")
		return
	}
	out.Done = true
	out.DoneJSON = doneJSON(rc.rt, rc.result)
	if !isHTTP {
		out.Summary = append(out.Summary, "$done() 已调用")
		return
	}
	res, err := rc.parseDone(resp == nil)
	if err != nil {
		out.OK, out.Error = false, err.Error()
		return
	}
	if res.Abort {
		out.Summary = append(out.Summary, "脚本中止了请求（ctx.abort）")
		return
	}
	if resp == nil {
		if res.Response != nil {
			m := &DebugHTTP{Status: res.Response.Status, Headers: headerMap(res.Response.Header)}
			if m.Status == 0 {
				m.Status = 200
			}
			m.Body, m.BodyBase64 = bodyOut(res.Response.Body)
			out.Mock = m
			out.Summary = append(out.Summary, fmt.Sprintf("本地应答：HTTP %d，%d 字节（不会请求服务器）", m.Status, len(res.Response.Body)))
			return
		}
		r := &DebugHTTP{URL: req.URL, Method: req.Method, Headers: headerMap(req.Header)}
		if res.URL != "" && res.URL != req.URL {
			r.URL = res.URL
			out.Summary = append(out.Summary, "URL 改为 "+clip(res.URL, 200))
		}
		if res.Method != "" && !strings.EqualFold(res.Method, req.Method) {
			r.Method = strings.ToUpper(res.Method)
			out.Summary = append(out.Summary, "方法改为 "+r.Method)
		}
		if res.Header != nil {
			r.Headers = headerMap(res.Header)
			out.Summary = append(out.Summary, fmt.Sprintf("请求头已替换（%d 个）", len(res.Header)))
		}
		b := req.Body
		if res.BodySet {
			b = res.Body
			out.Summary = append(out.Summary, fmt.Sprintf("请求体已修改（%d → %d 字节）", len(req.Body), len(res.Body)))
		}
		r.Body, r.BodyBase64 = bodyOut(b)
		out.Result = r
	} else {
		r := &DebugHTTP{Status: resp.Status, Headers: headerMap(resp.Header)}
		if res.Status != 0 && res.Status != resp.Status {
			r.Status = res.Status
			out.Summary = append(out.Summary, fmt.Sprintf("状态码改为 %d", res.Status))
		}
		if res.Header != nil {
			r.Headers = headerMap(res.Header)
			out.Summary = append(out.Summary, fmt.Sprintf("响应头已替换（%d 个）", len(res.Header)))
		}
		b := resp.Body
		if res.BodySet {
			b = res.Body
			out.Summary = append(out.Summary, fmt.Sprintf("响应体已修改（%d → %d 字节）", len(resp.Body), len(res.Body)))
		}
		r.Body, r.BodyBase64 = bodyOut(b)
		out.Result = r
	}
	if len(out.Summary) == 0 {
		out.Summary = append(out.Summary, "$done() 未做修改：原样放行")
	}
	return
}

// doneJSON renders the $done argument for display (long strings clipped, binary shown as a size).
func doneJSON(rt *goja.Runtime, v goja.Value) string {
	if v == nil || goja.IsUndefined(v) {
		return "undefined"
	}
	if goja.IsNull(v) {
		return "null"
	}
	var walk func(x any, depth int) any
	walk = func(x any, depth int) any {
		if depth > 8 {
			return "…"
		}
		switch t := x.(type) {
		case string:
			return clip(t, 2000)
		case []byte:
			return fmt.Sprintf("<%d 字节二进制>", len(t))
		case goja.ArrayBuffer:
			return fmt.Sprintf("<%d 字节二进制>", len(t.Bytes()))
		case map[string]any:
			m := make(map[string]any, len(t))
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				m[k] = walk(t[k], depth+1)
			}
			return m
		case []any:
			if len(t) > 200 {
				t = t[:200]
			}
			o := make([]any, len(t))
			for i := range t {
				o[i] = walk(t[i], depth+1)
			}
			return o
		default:
			return t
		}
	}
	b, err := json.MarshalIndent(walk(v.Export(), 0), "", "  ")
	if err != nil {
		return clip(v.String(), 2000)
	}
	return string(b)
}

func directDial(ctx context.Context, network, addr, policy string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// ScriptSource returns a script's code for the workbench: local scripts from the scripts folder, remote
// ones from the engine cache (downloaded directly when not cached yet).
func ScriptSource(home, path string) ([]byte, error) {
	e := New(home, directDial, func(string, string) {})
	return e.res.Get(path, 0)
}
