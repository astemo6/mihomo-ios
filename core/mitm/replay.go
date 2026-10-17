package mitm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ReplayRequest optionally edits a captured request before it is sent again.
type ReplayRequest struct {
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *string           `json:"body,omitempty"`
	Policy  string            `json:"policy,omitempty"`
}

// ReplayResult is what the app shows after a replay.
type ReplayResult struct {
	ID       int64             `json:"id"` // new request-log entry
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body,omitempty"`
	Binary   int               `json:"binary,omitempty"`
	Length   int               `json:"length"`
	Duration float64           `json:"duration"` // ms
	Error    string            `json:"error,omitempty"`
}

// Replay re-sends captured request id (optionally edited) straight upstream through the core
// (INNER, so the user's rules / policies apply but the engine's own rewrites do not).
func (e *Engine) Replay(id int64, edit *ReplayRequest) (*ReplayResult, error) {
	src := e.Requests.Get(id)
	if src == nil {
		return nil, fmt.Errorf("请求不存在（可能已被新的请求挤出记录）")
	}
	src.mu.Lock()
	method, u, hdr, body := src.Method, src.URL, map[string]string{}, src.ReqBodyS
	for k, v := range src.ReqHdr {
		hdr[k] = v
	}
	bin, full, dropped := src.ReqBin, src.ReqLen, src.Dropped
	src.mu.Unlock()
	if method == "TLS" {
		return nil, fmt.Errorf("这条记录是握手失败，没有可重放的请求")
	}
	if edit != nil {
		if edit.Method != "" {
			method = strings.ToUpper(edit.Method)
		}
		if edit.URL != "" {
			u = edit.URL
		}
		if edit.Headers != nil {
			hdr = edit.Headers
		}
		if edit.Body != nil {
			body, bin, full = *edit.Body, 0, len(*edit.Body)
		}
	}
	if bin > 0 {
		return nil, fmt.Errorf("请求体是二进制数据，未被记录，无法重放")
	}
	if dropped && full > len(body) {
		return nil, fmt.Errorf("请求体已因抓取内存上限从记录中移除，无法完整重放")
	}
	if full > len(body) {
		return nil, fmt.Errorf("请求体超过 %d KB 记录上限，无法完整重放", captureLimit/1024)
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
		return nil, fmt.Errorf("URL 无效：%s", u)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var rb io.Reader
	if body != "" {
		rb = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rb)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		switch strings.ToLower(k) {
		case "content-length", "accept-encoding", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":
			continue
		case "host":
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	ent := &Entry{ID: e.Requests.seq.Add(1), Time: float64(time.Now().UnixMilli()) / 1000, Method: method, URL: u, Host: pu.Hostname(),
		MitM: pu.Scheme == "https", start: time.Now(), ring: e.Requests, Notes: []string{fmt.Sprintf("重放 #%d", id)}}
	ent.ReqHdr = flatHeaders(req.Header)
	if body != "" {
		ent.ReqBody([]byte(body))
	}
	e.Requests.push(ent)
	policy := ""
	if edit != nil {
		policy = edit.Policy
	}
	start := time.Now()
	e.tmu.Lock()
	skip := e.tSkip
	e.tmu.Unlock()
	resp, err := e.client(policy, skip).Do(req)
	res := &ReplayResult{ID: ent.ID, Headers: map[string]string{}}
	if err != nil {
		res.Error = shortErr(err)
		res.Duration = float64(time.Since(start).Microseconds()) / 1000
		ent.Finish(0, "重放失败："+res.Error)
		return res, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	res.Status = resp.StatusCode
	res.Headers = flatHeaders(resp.Header)
	res.Length = len(b)
	res.Body, res.Binary = textOrBinary(b)
	res.Duration = float64(time.Since(start).Microseconds()) / 1000
	ent.Response(resp.StatusCode, resp.Header)
	ent.RespBody(b, "")
	ent.AddBytes(len(b))
	ent.Finish(resp.StatusCode, "")
	return res, nil
}
