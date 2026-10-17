package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/itchyny/gojq"
	"github.com/klauspost/compress/zstd"
)

// MaxBody caps any body the engine buffers for rewrite / scripts (memory guard for the ~50 MB extension).
const MaxBody = 2 << 20

var tinyGIF = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
	0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b}

func (r *Rule) match(u string) bool {
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
	bodyLoaded := false
	loadBody := func(limit int) bool {
		if bodyLoaded {
			return reqBody != nil || r.Body == nil || r.Body == http.NoBody
		}
		bodyLoaded = true
		if r.Body == nil || r.Body == http.NoBody {
			return true
		}
		b, rest, ok := readCapped(r.Body, limit)
		if !ok {
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(b), rest), r.Body}
			return false
		}
		reqBody = b
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		return true
	}
	setBody := func(b []byte) {
		reqBody = b
		bodyLoaded = true
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}
	var respRules []*Rule
	for _, rule := range rules {
		if rule.Phase == "response" {
			if rule.Kind != KindURL && rule.Kind != KindMapLocal && rule.matchReq(u, r) {
				respRules = append(respRules, rule)
			}
			continue
		}
		switch rule.Kind {
		case KindHeader:
			if rule.matchReq(u, r) {
				ent.Match(rule.label())
				applyHeaderOps(r.Header, rule.Headers, func() string { return r.Method + " " + r.URL.RequestURI() + " HTTP/1.1" })
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
			sreq := &ScriptHTTP{URL: u, Method: r.Method, Header: r.Header}
			if rule.Script.RequiresBody {
				lim := MaxBody
				if rule.Script.MaxSize > 0 && rule.Script.MaxSize < lim {
					lim = rule.Script.MaxSize
				}
				if !loadBody(lim) {
					e.Logs.Add(rule.Script.Name, "warn", "请求体超过上限，跳过脚本")
					continue
				}
				sreq.Body, sreq.HasBody = reqBody, true
			}
			ent.Match(rule.label())
			res, err := e.scripts.Run(r.Context(), rule, sreq, nil)
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
				if code == 0 {
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
			}
			if res.BodySet {
				setBody(res.Body)
			}
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
	rp.ServeHTTP(w, r)
}

const captureLimit = 32 * 1024

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
	var body []byte
	loaded, tooBig := false, false
	loadBody := func(limit int) bool {
		if loaded {
			return !tooBig
		}
		loaded = true
		b, rest, ok := readCapped(resp.Body, limit)
		if !ok {
			tooBig = true
			resp.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(b), rest), resp.Body}
			return false
		}
		_ = resp.Body.Close()
		dec, err := decodeBody(resp.Header.Get("Content-Encoding"), b)
		if err != nil {
			// leave the body untouched
			tooBig = true
			resp.Body = io.NopCloser(bytes.NewReader(b))
			return false
		}
		if len(dec) != len(b) || resp.Header.Get("Content-Encoding") != "" {
			resp.Header.Del("Content-Encoding")
		}
		body = dec
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return true
	}
	setBody := func(b []byte) {
		body = b
		loaded = true
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
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
			sreq := &ScriptHTTP{URL: f.url, Method: resp.Request.Method, Header: resp.Request.Header}
			sresp := &ScriptHTTP{Status: resp.StatusCode, Header: resp.Header}
			if rule.Script.RequiresBody {
				lim := MaxBody
				if rule.Script.MaxSize > 0 && rule.Script.MaxSize < lim {
					lim = rule.Script.MaxSize
				}
				if !loadBody(lim) {
					e.Logs.Add(rule.Script.Name, "warn", "响应体超过上限或编码不支持，跳过脚本")
					continue
				}
				sresp.Body, sresp.HasBody = body, true
			}
			ent.Match(rule.label())
			res, err := e.scripts.Run(resp.Request.Context(), rule, sreq, sresp)
			if err != nil {
				e.Logs.Add(rule.Script.Name, "error", err.Error())
				ent.Note("脚本错误：" + rule.Script.Name)
				continue
			}
			if res.Abort {
				ent.Note("脚本中止：" + rule.Script.Name)
				return fmt.Errorf("脚本 %s 中止了响应", rule.Script.Name)
			}
			if res.Status > 0 {
				resp.StatusCode = res.Status
				resp.Status = fmt.Sprintf("%d %s", res.Status, http.StatusText(res.Status))
			}
			if res.Header != nil {
				resp.Header = res.Header
				resp.Header.Del("Content-Length")
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

func decodeBody(enc string, b []byte) ([]byte, error) {
	enc = strings.ToLower(strings.TrimSpace(enc))
	var r io.Reader
	switch enc {
	case "", "identity":
		return b, nil
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		r = gr
	case "deflate":
		r = flate.NewReader(bytes.NewReader(b))
	case "br":
		r = brotli.NewReader(bytes.NewReader(b))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		return nil, fmt.Errorf("不支持的编码 %s", enc)
	}
	out, err := io.ReadAll(io.LimitReader(r, 4*MaxBody))
	return out, err
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
		s := string(body)
		for _, op := range rule.Body {
			if op.re == nil {
				continue
			}
			ns, err := op.re.Replace(s, op.Repl, -1, -1)
			if err != nil {
				return nil, err
			}
			s = ns
		}
		return []byte(s), nil
	case KindJQ:
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
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, fmt.Errorf("不是 JSON")
		}
		for _, op := range rule.JSON {
			v = jsonEdit(v, splitJSONPath(op.Path), op.Op, parseJSONValue(op.Value))
		}
		return json.Marshal(v)
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
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
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
	return json.Marshal(out)
}

func parseJSONValue(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
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
