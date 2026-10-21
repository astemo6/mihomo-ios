package mitm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/itchyny/gojq"
)

// MaxBody caps any body the engine buffers for rewrite / scripts (memory guard for the ~50 MB extension).
const MaxBody = 2 << 20

// MaxScriptBody is the body cap for a script that asks for unlimited / larger bodies (max-size=-1, or a
// max-size above MaxBody): Sub-Store's backend receives whole backups and files in a POST body.
const MaxScriptBody = 4 << 20

// scriptBodyLimit is the body size handed to a requires-body script: its max-size within the caps.
func scriptBodyLimit(sc *Script) int {
	switch {
	case sc.MaxSize < 0 || sc.MaxSize > MaxScriptBody:
		return MaxScriptBody
	case sc.MaxSize == 0:
		return MaxBody
	}
	return sc.MaxSize
}

// phaseBodyCap is the read cap for one phase's body: MaxBody, raised to a requires-body script's
// scriptBodyLimit (up to MaxScriptBody) when such a script is among the phase's rules. Rewrites still
// only take bodies up to MaxBody; the cap only decides how much is read (under the shared budget).
func phaseBodyCap(rules []*Rule, phase string) int {
	c := MaxBody
	for _, r := range rules {
		if r.Kind == KindScript && r.Script != nil && r.Script.RequiresBody && (phase == "" || r.Phase == phase) {
			if l := scriptBodyLimit(r.Script); l > c {
				c = l
			}
		}
	}
	return c
}

var tinyGIF = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b}

func (r *Rule) match(u string) bool {
	if r.fre != nil {
		// r7 OPT-1: RE2 on the string (no []rune copy per rule per request).
		return r.fre.MatchString(u)
	}
	if r.re == nil {
		return false
	}
	ok, err := r.re.MatchString(u)
	return err == nil && ok
}

// matchReq is match plus the QX url-and-header condition on the request line and headers.
func (r *Rule) matchReq(u string, req *http.Request) bool {
	if !r.match(u) {
		return false
	}
	if r.hre == nil {
		return true
	}
	if req == nil {
		return false
	}
	var b strings.Builder
	b.WriteString(req.Method + " " + req.URL.RequestURI() + " HTTP/1.1\r\n")
	if req.Host != "" {
		b.WriteString("Host: " + req.Host + "\r\n")
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	ok, err := r.hre.MatchString(b.String())
	return err == nil && ok
}

func (r *Rule) label() string {
	if r.Source != "" && r.Source != "用户" {
		return r.Desc + " · " + r.Source
	}
	return r.Desc
}

type flowKey struct{}

type flow struct {
	st    *state
	ent   *Entry
	url   string
	rules []*Rule // response-phase rules matched against the final request URL
	// release returns the flow's share of the body budget (set once the response body is loaded).
	release func()
}

func requestURL(r *http.Request, meta *connMeta) string {
	scheme := "http"
	if meta != nil && meta.tls {
		scheme = "https"
	}
	host := r.Host
	if host == "" && meta != nil {
		host = meta.host
		if meta.port != 0 && !(scheme == "https" && meta.port == 443) && !(scheme == "http" && meta.port == 80) {
			host = net.JoinHostPort(meta.host, strconv.Itoa(meta.port))
		}
	}
	if h, p, err := net.SplitHostPort(host); err == nil && (scheme == "https" && p == "443" || scheme == "http" && p == "80") {
		host = h
	}
	return scheme + "://" + host + r.URL.RequestURI()
}

func (e *Engine) serveHTTP(w http.ResponseWriter, r *http.Request) {
	st := e.state()
	meta, _ := r.Context().Value(metaKey{}).(*connMeta)
	u := requestURL(r, meta)
	ent := e.Requests.Start(r, u, meta != nil && meta.tls)
	defer func() {
		if p := recover(); p != nil {
			if p == http.ErrAbortHandler {
				ent.Finish(0, "已断开")
				panic(p)
			}
			e.logf("error", fmt.Sprintf("[MitM] 处理 %s 时出错：%v", clip(u, 100), p))
			ent.Finish(502, "内部错误")
			http.Error(w, "mitm error", http.StatusBadGateway)
		}
	}()
	capture := st.cfg.capture()

	rules := st.rs.Rules
	if !st.cfg.Enabled {
		rules = nil
	}

	// 1. URL rewrite — first match wins.
	for _, rule := range rules {
		if rule.Kind != KindURL || !rule.matchReq(u, r) {
			continue
		}
		ent.Match(rule.label())
		switch rule.Action {
		case "reject-drop":
			ent.Finish(0, "拒绝（断开）")
			panic(http.ErrAbortHandler)
		case "reject", "reject-200", "reject-img", "reject-dict", "reject-array":
			status, ctype, body := 404, "text/plain", []byte{}
			switch rule.Action {
			case "reject-200":
				status = 200
			case "reject-img":
				status, ctype, body = 200, "image/gif", tinyGIF
			case "reject-dict":
				status, ctype, body = 200, "application/json", []byte("{}")
			case "reject-array":
				status, ctype, body = 200, "application/json", []byte("[]")
			}
			writeLocal(w, status, http.Header{"Content-Type": {ctype}}, body)
			ent.Local(status, w.Header(), body, capture)
			return
		case "302", "307":
			loc, err := rule.re.Replace(u, rule.Target, -1, 1)
			if err != nil {
				loc = rule.Target
			}
			code := http.StatusFound
			if rule.Action == "307" {
				code = http.StatusTemporaryRedirect
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(code)
			ent.Local(code, w.Header(), nil, capture)
			return
		case "header":
			nu, err := rule.re.Replace(u, rule.Target, -1, 1)
			if err == nil {
				if pu, err := url.Parse(nu); err == nil && pu.Host != "" {
					u = nu
					r.URL = pu
					r.Host = pu.Host
					ent.SetURL(u)
				}
			}
		}
		break
	}

	// 2. Map Local — first match wins.
	for _, rule := range rules {
		if rule.Kind != KindMapLocal || !rule.matchReq(u, r) {
			continue
		}
		ent.Match(rule.label())
		if e.serveLargeMapLocal(w, rule, ent, capture) {
			return
		}
		body, ctype, err := e.mapLocalData(rule)
		if err != nil {
			e.logf("warning", fmt.Sprintf("[MitM] 本地映射数据读取失败：%s", err))
		}
		h := http.Header{}
		for k, v := range rule.RespHeaders {
			h.Set(k, v)
		}
		if h.Get("Content-Type") == "" && ctype != "" {
			h.Set("Content-Type", ctype)
		}
		st := rule.Status
		if st == 0 {
			st = 200
		}
		writeLocal(w, st, h, body)
		ent.Local(st, h, body, capture)
		return
	}

	// 3. Request phase: header rewrites, body rewrites and scripts in rule order.
	var reqBody []byte
	bodyLoaded, bodyOK := false, false
	var releaseReq func()
	defer func() {
		if releaseReq != nil {
			releaseReq()
		}
	}()
	// review5 P0-1 / P2-2: the body is read once, with reqCap (MaxBody, or a max-size=-1 script's
	// MaxScriptBody), after taking a share of the global body budget. Each caller's limit (MaxBody for
	// rewrites, scriptBodyLimit for scripts) is compared against the loaded length.
	reqCap := phaseBodyCap(rules, "request")
	loadBody := func(limit int) bool {
		if bodyLoaded {
			return bodyOK && len(reqBody) <= limit
		}
		bodyLoaded = true
		if r.Body == nil || r.Body == http.NoBody {
			bodyOK = true
			return true
		}
		if heapHigh() {
			e.logf("warning", fmt.Sprintf("[MitM] 内存紧张，跳过请求体处理：%s", clip(u, 100)))
			return false
		}
		want := int64(reqCap)
		if r.ContentLength > 0 && r.ContentLength < want {
			want = r.ContentLength
		}
		if r.ContentLength > int64(limit) {
			bodyLoaded = false // a later rule with a larger limit may still read it
			return false
		}
		if r.ContentLength > int64(reqCap) {
			return false
		}
		rel := bodyBudget.acquire(r.Context(), want, bodyBudgetWait)
		if rel == nil {
			e.logf("warning", fmt.Sprintf("[MitM] 同时处理的请求/响应体过多，跳过：%s", clip(u, 100)))
			return false
		}
		releaseReq = rel
		b, rest, ok := readCapped(r.Body, reqCap)
		if !ok {
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(b), rest), r.Body}
			return false
		}
		reqBody = b
		bodyOK = true
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		return len(b) <= limit
	}
	setBody := func(b []byte) {
		reqBody = b
		bodyLoaded, bodyOK = true, true
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}
	for _, rule := range rules {
		if rule.Phase == "response" {
			continue // matched below against the final URL
		}
		switch rule.Kind {
		case KindHeader:
			if rule.matchReq(u, r) {
				ent.Match(rule.label())
				// review5 P2-4: Go keeps Host in r.Host; expose it to the ops and take changes back.
				if r.Header.Get("Host") == "" {
					r.Header.Set("Host", r.Host)
				}
				applyHeaderOps(r.Header, rule.Headers, func() string { return r.Method + " " + r.URL.RequestURI() + " HTTP/1.1" })
				if h := r.Header.Get("Host"); h != "" {
					r.Host = h
				}
				r.Header.Del("Host")
			}
		case KindBody, KindJQ, KindJSON:
			if rule.matchReq(u, r) && loadBody(MaxBody) {
				nb, err := e.applyBodyRule(rule, reqBody)
				if err != nil {
					e.logf("warning", fmt.Sprintf("[MitM] 请求体改写失败（%s）：%s", rule.Desc, err))
					continue
				}
				ent.Match(rule.label())
				setBody(nb)
			}
		case KindScript:
			if !rule.matchReq(u, r) {
				continue
			}
			sreq := &ScriptHTTP{URL: u, Method: r.Method, Header: r.Header, Host: r.Host}
			// review5 P0-1: take the script slot before loading the body, so queued scripts don't
			// each hold a body while they wait.
			slot, err := e.scripts.Reserve(r.Context(), rule)
			if err != nil {
				e.Logs.Add(rule.Script.Name, "error", err.Error())
				ent.Note("脚本错误：" + rule.Script.Name)
				continue
			}
			if rule.Script.RequiresBody {
				if !loadBody(scriptBodyLimit(rule.Script)) {
					slot.Release()
					e.Logs.Add(rule.Script.Name, "warn", "请求体超过上限，跳过脚本")
					continue
				}
				sreq.Body, sreq.HasBody = reqBody, true
			}
			ent.Match(rule.label())
			res, err := e.scripts.RunReserved(r.Context(), slot, rule, sreq, nil)
			slot.Release()
			if err != nil {
				e.Logs.Add(rule.Script.Name, "error", err.Error())
				ent.Note("脚本错误：" + rule.Script.Name)
				continue
			}
			if res.Abort {
				ent.Finish(0, "脚本中止："+rule.Script.Name)
				panic(http.ErrAbortHandler)
			}
			if res.Response != nil {
				h := res.Response.Header
				if h == nil {
					h = http.Header{}
				}
				code := res.Response.Status
				if !validScriptStatus(code) {
					if code != 0 {
						e.Logs.Add(rule.Script.Name, "warn", fmt.Sprintf("脚本返回的状态码 %d 无效，按 200 处理", code))
					}
					code = 200
				}
				writeLocal(w, code, h, res.Response.Body)
				ent.Local(code, h, res.Response.Body, capture)
				return
			}
			if res.URL != "" && res.URL != u {
				if pu, err := url.Parse(res.URL); err == nil && pu.Host != "" {
					u = res.URL
					r.URL = pu
					r.Host = pu.Host
					ent.SetURL(u)
				}
			}
			if res.Method != "" {
				r.Method = strings.ToUpper(res.Method)
			}
			if res.Header != nil {
				r.Header = res.Header
				// review5 P2-4: scripts see / set Host through the headers.
				if h := r.Header.Get("Host"); h != "" {
					r.Host = h
				}
				r.Header.Del("Host")
			}
			if res.BodySet {
				setBody(res.Body)
			}
		}
	}

	// r7 P3-2: response-phase rules are matched once the request phase is over, against the final URL
	// and headers. Collected inside the loop above, a response rule listed before a URL-changing request
	// script was matched against the old URL.
	var respRules []*Rule
	for _, rule := range rules {
		if rule.Phase == "response" && rule.Kind != KindURL && rule.Kind != KindMapLocal && rule.matchReq(u, r) {
			respRules = append(respRules, rule)
		}
	}

	if capture {
		if reqBody != nil {
			ent.ReqBody(reqBody)
		} else if r.ContentLength > 0 && r.ContentLength <= captureLimit && r.Body != nil {
			if b, rest, ok := readCapped(r.Body, captureLimit); ok {
				ent.ReqBody(b)
				r.Body = io.NopCloser(bytes.NewReader(b))
			} else {
				r.Body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(b), rest), r.Body}
			}
		}
	}
	ent.ReqHeaders(r.Method, r.Header)

	needRespBody := false
	for _, rule := range respRules {
		if rule.Kind == KindBody || rule.Kind == KindJQ || rule.Kind == KindJSON || (rule.Kind == KindScript && rule.Script.RequiresBody) {
			needRespBody = true
		}
	}
	if needRespBody {
		// Only ask for encodings we can decode.
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	f := &flow{st: st, ent: ent, url: u, rules: respRules}
	defer func() {
		if f.release != nil {
			f.release()
		}
	}()
	target, _ := url.Parse(u)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Host = r.Host
			if pr.Out.Header.Get("User-Agent") == "" {
				pr.Out.Header["User-Agent"] = nil
			}
		},
		Transport:     e.upstream(),
		FlushInterval: -1,
		ErrorLog:      nil,
		ModifyResponse: func(resp *http.Response) error {
			return e.modifyResponse(f, resp)
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if err == context.Canceled {
				ent.Finish(0, "客户端取消")
				return
			}
			ent.Finish(502, "上游错误："+shortErr(err))
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	// The rewrite / script work on the request body is done: hand its budget back before waiting on
	// upstream (the bytes are only streamed from here on).
	if releaseReq != nil {
		releaseReq()
	}
	rp.ServeHTTP(w, r)
}

const captureLimit = 32 * 1024

// upstreamDrainMax: an upstream body replaced by a script is read to its end before closing when its
// announced length is at most this (keeps the HTTP/1.1 connection reusable); longer ones are just closed.
const upstreamDrainMax = 256 << 10

// validScriptStatus: a final HTTP status a script may set (review6 P2-1). net/http panics on codes outside
// 100–999 and 1xx is not a final response, so anything else was a 502 「mitm error」.
func validScriptStatus(code int) bool { return code >= 200 && code <= 999 }

func writeLocal(w http.ResponseWriter, status int, h http.Header, body []byte) {
	for k, v := range h {
		w.Header()[k] = v
	}
	w.Header().Del("Content-Encoding")
	w.Header().Del("Transfer-Encoding")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// readCapped reads up to limit bytes. ok=false when the body is larger (b holds what was read, rest the remainder).
func readCapped(rc io.Reader, limit int) (b []byte, rest io.Reader, ok bool) {
	buf := &bytes.Buffer{}
	n, err := io.CopyN(buf, rc, int64(limit)+1)
	if err != nil && err != io.EOF {
		return buf.Bytes(), rc, false
	}
	if n > int64(limit) {
		return buf.Bytes(), rc, false
	}
	return buf.Bytes(), nil, true
}

func (e *Engine) modifyResponse(f *flow, resp *http.Response) error {
	ent := f.ent
	if resp.StatusCode == http.StatusSwitchingProtocols {
		ent.Response(resp.StatusCode, resp.Header)
		ent.Finish(101, "WebSocket / Upgrade")
		return nil
	}
	capture := f.st.cfg.capture()
	defer func() {
		// Rules are done with the body once we return; from here it is only streamed to the client.
		if f.release != nil {
			f.release()
		}
	}()
	var body []byte
	loaded, tooBig := false, false
	// r7 P3-3: the upstream body is closed as soon as something else replaces it (a script's mock body),
	// after draining a small known-length rest so the upstream connection can be reused. ReverseProxy only
	// closes the body we hand it, so the original stayed open until the request context ended (one new
	// upstream TCP+TLS connection per mocked request).
	upstream := resp.Body
	upstreamDone := false
	closeUpstream := func() {
		if upstreamDone || upstream == nil {
			return
		}
		upstreamDone = true
		if resp.ContentLength >= 0 && resp.ContentLength <= upstreamDrainMax {
			_, _ = io.Copy(io.Discard, io.LimitReader(upstream, upstreamDrainMax+1))
		}
		_ = upstream.Close()
	}
	// review5 P0-1 / P1-1 / P2-2: loaded once with respCap (raw and decoded; MaxBody, or a
	// max-size=-1 script's MaxScriptBody), under the global body budget; a body that decodes past the
	// cap is passed through as is. Each caller's limit is compared against the loaded length.
	respCap := phaseBodyCap(f.rules, "")
	loadBody := func(limit int) bool {
		if loaded {
			return !tooBig && len(body) <= limit
		}
		loaded = true
		tooBig = true
		if heapHigh() {
			e.logf("warning", fmt.Sprintf("[MitM] 内存紧张，跳过响应体处理：%s", clip(f.url, 100)))
			return false
		}
		if resp.ContentLength > int64(limit) && resp.Header.Get("Content-Encoding") == "" {
			loaded = false // a later rule with a larger limit may still read it
			return false
		}
		if resp.ContentLength > int64(respCap) {
			return false
		}
		want := int64(respCap)
		if resp.ContentLength > 0 && resp.ContentLength < want && resp.Header.Get("Content-Encoding") == "" {
			want = resp.ContentLength
		}
		rel := bodyBudget.acquire(resp.Request.Context(), want, bodyBudgetWait)
		if rel == nil {
			e.logf("warning", fmt.Sprintf("[MitM] 同时处理的响应体过多，跳过：%s", clip(f.url, 100)))
			return false
		}
		f.release = rel
		b, rest, ok := readCapped(resp.Body, respCap)
		if !ok {
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(b), rest), resp.Body}
			return false
		}
		_ = resp.Body.Close()
		upstreamDone = true
		dec, err := decodeBody(resp.Header.Get("Content-Encoding"), b, respCap)
		if err != nil {
			// leave the body untouched (never pass on a truncated decode)
			if errors.Is(err, errBodyTooBig) {
				e.logf("warning", fmt.Sprintf("[MitM] 响应体解压后超过 %d KB，原样放行：%s", respCap>>10, clip(f.url, 100)))
			}
			resp.Body = io.NopCloser(bytes.NewReader(b))
			return false
		}
		if len(dec) != len(b) || resp.Header.Get("Content-Encoding") != "" {
			resp.Header.Del("Content-Encoding")
		}
		tooBig = false
		body = dec
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return len(body) <= limit
	}
	// r7 P3-1: a response that carries no body by definition (HEAD, 204, 304) keeps its framing headers:
	// its Content-Length describes the entity a GET would return (download size probes), not this body.
	noBody := resp.Request.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified
	setBody := func(b []byte) {
		body = b
		loaded = true
		if noBody {
			return
		}
		closeUpstream()
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
		// review6 P1-3: whatever we hand on is plain bytes (a decoded load, a rewrite or a script's body).
		// A script without requires-body that returns a body left the upstream's gzip/br label on it.
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Transfer-Encoding")
		resp.TransferEncoding = nil
	}

	for _, rule := range f.rules {
		switch rule.Kind {
		case KindHeader:
			ent.Match(rule.label())
			applyHeaderOps(resp.Header, rule.Headers, func() string { return "HTTP/1.1 " + resp.Status })
		case KindBody, KindJQ, KindJSON:
			if !loadBody(MaxBody) {
				e.logf("warning", fmt.Sprintf("[MitM] 响应体超过 %d KB 或编码不支持，跳过：%s", MaxBody>>10, rule.Desc))
				continue
			}
			nb, err := e.applyBodyRule(rule, body)
			if err != nil {
				e.logf("warning", fmt.Sprintf("[MitM] 响应体改写失败（%s）：%s", rule.Desc, err))
				continue
			}
			ent.Match(rule.label())
			setBody(nb)
		case KindScript:
			sreq := &ScriptHTTP{URL: f.url, Method: resp.Request.Method, Header: resp.Request.Header, Host: resp.Request.Host}
			sresp := &ScriptHTTP{Status: resp.StatusCode, Header: resp.Header}
			slot, err := e.scripts.Reserve(resp.Request.Context(), rule)
			if err != nil {
				e.Logs.Add(rule.Script.Name, "error", err.Error())
				ent.Note("脚本错误：" + rule.Script.Name)
				continue
			}
			if rule.Script.RequiresBody {
				if !loadBody(scriptBodyLimit(rule.Script)) {
					slot.Release()
					e.Logs.Add(rule.Script.Name, "warn", "响应体超过上限或编码不支持，跳过脚本")
					continue
				}
				sresp.Body, sresp.HasBody = body, true
			}
			ent.Match(rule.label())
			res, err := e.scripts.RunReserved(resp.Request.Context(), slot, rule, sreq, sresp)
			slot.Release()
			if err != nil {
				e.Logs.Add(rule.Script.Name, "error", err.Error())
				ent.Note("脚本错误：" + rule.Script.Name)
				continue
			}
			if res.Abort {
				ent.Note("脚本中止：" + rule.Script.Name)
				return fmt.Errorf("脚本 %s 中止了响应", rule.Script.Name)
			}
			if res.Status > 0 && !validScriptStatus(res.Status) {
				e.Logs.Add(rule.Script.Name, "warn", fmt.Sprintf("脚本返回的状态码 %d 无效，已忽略", res.Status))
			} else if res.Status > 0 {
				resp.StatusCode = res.Status
				resp.Status = fmt.Sprintf("%d %s", res.Status, http.StatusText(res.Status))
			}
			if res.Header != nil {
				resp.Header = res.Header
				if !noBody {
					resp.Header.Del("Content-Length")
				}
				if loaded && !tooBig {
					resp.Header.Del("Content-Encoding")
				}
			}
			if res.BodySet {
				setBody(res.Body)
			} else if loaded && !tooBig {
				setBody(body)
			}
		}
	}
	if loaded && !tooBig {
		setBody(body)
	}
	ent.Response(resp.StatusCode, resp.Header)
	if capture {
		if loaded && !tooBig {
			ent.RespBody(body, "")
		} else if resp.Body != nil {
			resp.Body = &captureBody{rc: resp.Body, ent: ent, enc: resp.Header.Get("Content-Encoding")}
			return nil
		}
	}
	resp.Body = &finishBody{rc: resp.Body, ent: ent}
	return nil
}

type finishBody struct {
	rc   io.ReadCloser
	ent  *Entry
	done bool
}

func (b *finishBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.ent.AddBytes(n)
	return n, err
}
func (b *finishBody) Close() error {
	if !b.done {
		b.done = true
		b.ent.Finish(-1, "")
	}
	return b.rc.Close()
}

type captureBody struct {
	rc   io.ReadCloser
	ent  *Entry
	enc  string
	buf  bytes.Buffer
	done bool
}

func (b *captureBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.ent.AddBytes(n)
		if room := captureLimit - b.buf.Len(); room > 0 {
			if room > n {
				room = n
			}
			b.buf.Write(p[:room])
		}
	}
	return n, err
}

func (b *captureBody) Close() error {
	if !b.done {
		b.done = true
		b.ent.RespBody(b.buf.Bytes(), b.enc)
		b.ent.Finish(-1, "")
	}
	return b.rc.Close()
}

// applyHeaderOps applies Surge / QX header operations. firstLine builds the request/status line
// QX raw-regex rules see at the top of the header block.
func applyHeaderOps(h http.Header, ops []HeaderOp, firstLine func() string) {
	for _, op := range ops {
		switch op.Op {
		case "add":
			h.Add(op.Name, op.Value)
		case "del":
			h.Del(op.Name)
		case "replace":
			if h.Get(op.Name) != "" {
				h.Set(op.Name, op.Value)
			}
		case "replace-regex":
			if v := h.Get(op.Name); v != "" && op.re != nil {
				if nv, err := op.re.Replace(v, op.Value, -1, -1); err == nil {
					h.Set(op.Name, nv)
				}
			}
		case "raw":
			if op.re == nil {
				continue
			}
			var sb strings.Builder
			sb.WriteString(firstLine())
			sb.WriteString("\r\n")
			for k, vs := range h {
				for _, v := range vs {
					sb.WriteString(k + ": " + v + "\r\n")
				}
			}
			sb.WriteString("\r\n")
			out, err := op.re.Replace(sb.String(), unescapeCRLF(op.Value), -1, -1)
			if err != nil {
				continue
			}
			for k := range h {
				delete(h, k)
			}
			lines := strings.Split(out, "\r\n")
			for _, l := range lines[1:] {
				if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) != "" {
					h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
				}
			}
		}
	}
}

func unescapeCRLF(s string) string {
	return strings.NewReplacer(`\r`, "\r", `\n`, "\n").Replace(s)
}

func (e *Engine) applyBodyRule(rule *Rule, body []byte) ([]byte, error) {
	switch rule.Kind {
	case KindBody:
		// review5 P0-1: byte-based Go regexp when the op allows it; the backtracking engine (which
		// copies the input to []rune, 4 B/char) only for small bodies.
		for _, op := range rule.Body {
			if op.fast != nil {
				body = op.fast.ReplaceAll(body, op.fastTmpl)
				continue
			}
			if op.re == nil {
				continue
			}
			if len(body) > regexp2BodyLimit {
				return nil, fmt.Errorf("该正则需回溯引擎，内容超过 %d KB，跳过", regexp2BodyLimit>>10)
			}
			ns, err := op.re.Replace(string(body), op.Repl, -1, -1)
			if err != nil {
				return nil, err
			}
			body = []byte(ns)
		}
		return body, nil
	case KindJQ:
		if err := jsonBodyFits(len(body)); err != nil {
			return nil, err
		}
		expr := rule.JQ
		if expr == "" && rule.Data != "" {
			b, err := e.res.Get(rule.Data, 86400)
			if err != nil {
				return nil, err
			}
			expr = string(b)
		}
		return runJQ(expr, body)
	case KindJSON:
		if err := jsonBodyFits(len(body)); err != nil {
			return nil, err
		}
		v, err := decodeJSONNumber(body)
		if err != nil {
			return nil, fmt.Errorf("不是 JSON")
		}
		for _, op := range rule.JSON {
			v = jsonEdit(v, splitJSONPath(op.Path), op.Op, parseJSONValue(op.Value))
		}
		return encodeJSON(v)
	}
	return body, nil
}

var jqCache = newLRU[*gojq.Code](32)

func runJQ(expr string, body []byte) ([]byte, error) {
	code, ok := jqCache.Get(expr)
	if !ok {
		q, err := gojq.Parse(expr)
		if err != nil {
			return nil, fmt.Errorf("jq 语法错误：%w", err)
		}
		code, err = gojq.Compile(q)
		if err != nil {
			return nil, err
		}
		jqCache.Put(expr, code)
	}
	v, err := decodeJSONNumber(body)
	if err != nil {
		return nil, fmt.Errorf("不是 JSON")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	iter := code.RunWithContext(ctx, v)
	out, ok := iter.Next()
	if !ok {
		return body, nil
	}
	if err, ok := out.(error); ok {
		return nil, err
	}
	return encodeJSON(out)
}

func parseJSONValue(s string) any {
	if v, err := decodeJSONNumber([]byte(s)); err == nil {
		return v
	}
	return s
}

// splitJSONPath turns "data.list[0].ad" into ["data","list",0,"ad"].
func splitJSONPath(p string) []any {
	var out []any
	for _, part := range strings.Split(strings.TrimPrefix(p, "$."), ".") {
		for part != "" {
			i := strings.IndexByte(part, '[')
			if i < 0 {
				out = append(out, part)
				break
			}
			if i > 0 {
				out = append(out, part[:i])
			}
			j := strings.IndexByte(part, ']')
			if j < i {
				out = append(out, part)
				break
			}
			if n, err := strconv.Atoi(part[i+1 : j]); err == nil {
				out = append(out, n)
			} else {
				out = append(out, strings.Trim(part[i+1:j], `"'`))
			}
			part = part[j+1:]
		}
	}
	return out
}

func jsonEdit(v any, p []any, op string, val any) any {
	if len(p) == 0 {
		if op == "replace" || op == "add" {
			return val
		}
		return v
	}
	switch key := p[0].(type) {
	case string:
		m, ok := v.(map[string]any)
		if !ok {
			return v
		}
		if len(p) == 1 {
			switch op {
			case "del":
				delete(m, key)
			case "replace":
				if _, ok := m[key]; ok {
					m[key] = val
				}
			case "add":
				m[key] = val
			}
			return m
		}
		if child, ok := m[key]; ok {
			m[key] = jsonEdit(child, p[1:], op, val)
		} else if op == "add" {
			m[key] = jsonEdit(map[string]any{}, p[1:], op, val)
		}
		return m
	case int:
		a, ok := v.([]any)
		if !ok || key < 0 || key >= len(a) {
			return v
		}
		if len(p) == 1 {
			switch op {
			case "del":
				return append(a[:key], a[key+1:]...)
			default:
				a[key] = val
			}
			return a
		}
		a[key] = jsonEdit(a[key], p[1:], op, val)
		return a
	}
	return v
}

func (e *Engine) mapLocalData(rule *Rule) ([]byte, string, error) {
	switch rule.DataType {
	case "tiny-gif":
		return tinyGIF, "image/gif", nil
	case "base64":
		b, err := base64.StdEncoding.DecodeString(rule.Data)
		return b, "application/octet-stream", err
	case "text":
		return []byte(rule.Data), guessTextType(rule.Data), nil
	case "json":
		return []byte(rule.Data), "application/json", nil
	default: // file / URL
		if rule.Data == "" {
			return nil, "text/plain", nil
		}
		b, err := e.res.Get(rule.Data, 86400)
		return b, guessType(rule.Data, b), err
	}
}

// serveLargeMapLocal streams a map-local file of memCacheMax or more from disk (r7 B26). Such files are
// not kept in the resource memory cache, so every matching request read the whole file (up to 8 MB)
// into memory outside the body budget; now the response is copied from the file with a small buffer.
// false: not a large file on disk — the caller serves it from memory as before.
func (e *Engine) serveLargeMapLocal(w http.ResponseWriter, rule *Rule, ent *Entry, capture bool) bool {
	if rule.DataType != "" && rule.DataType != "file" || rule.Data == "" {
		return false
	}
	p := rule.Data
	if isRemote(p) {
		p = CachePath(e.home, rule.Data)
	} else {
		p = e.res.LocalPath(p)
	}
	f, err := os.Open(p)
	if err != nil {
		return false // not downloaded yet: mapLocalData fetches it
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() < memCacheMax {
		return false
	}
	if isRemote(rule.Data) {
		e.res.RefreshIfStale(rule.Data, 86400)
	}
	head := make([]byte, min(int64(captureLimit), fi.Size()))
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false
	}
	h := w.Header()
	for k, v := range rule.RespHeaders {
		h.Set(k, v)
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", guessType(rule.Data, head))
	}
	h.Del("Content-Encoding")
	h.Del("Transfer-Encoding")
	h.Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	st := rule.Status
	if st == 0 {
		st = 200
	}
	w.WriteHeader(st)
	written, _ := io.Copy(w, io.LimitReader(f, fi.Size()))
	ent.Local(st, h, nil, false)
	ent.AddBytes(int(written))
	if capture {
		ent.RespBody(head, "")
	}
	return true
}

func guessTextType(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return "application/json"
	}
	if strings.HasPrefix(t, "<") {
		return "text/html; charset=utf-8"
	}
	return "text/plain; charset=utf-8"
}

func guessType(p string, b []byte) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".json":
		return "application/json"
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".js":
		return "application/javascript"
	case ".gif":
		return "image/gif"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".txt":
		return "text/plain; charset=utf-8"
	}
	return http.DetectContentType(b)
}
