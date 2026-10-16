package mitm

// Visual rewrite editor (本地模块): one form model <-> one canonical Surge-syntax line. The line is what
// gets stored (engine.json rules, the user's local module), so the raw-text view, modules and the
// engine all read the same thing; FormFromLine accepts any syntax ParseLine understands (Surge, QX,
// Loon, Stash) and maps it onto the form when the rule fits one, otherwise the UI edits it as text.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RewriteForm is the editor model.
type RewriteForm struct {
	Type    string `json:"type"` // reject / redirect / header / body / maplocal / raw
	Pattern string `json:"pattern"`
	Phase   string `json:"phase,omitempty"`  // header / body: request / response
	Action  string `json:"action,omitempty"` // reject*: reject reject-200 reject-img reject-dict reject-array reject-drop; redirect: 302 / 307
	Target  string `json:"target,omitempty"` // redirect target

	HeaderOp    string `json:"headerOp,omitempty"` // add / del / replace / replace-regex
	HeaderName  string `json:"headerName,omitempty"`
	HeaderValue string `json:"headerValue,omitempty"`
	HeaderRegex string `json:"headerRegex,omitempty"`

	Regex       string `json:"regex,omitempty"` // body
	Replacement string `json:"replacement,omitempty"`

	Data        string `json:"data,omitempty"`     // map local: inline data
	DataType    string `json:"dataType,omitempty"` // text / base64 / file / tiny-gif
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Headers     string `json:"headers,omitempty"` // extra map-local headers "A:b|C:d"

	Line  string `json:"line,omitempty"`  // raw / output
	Error string `json:"error,omitempty"` // validation error
	Desc  string `json:"desc,omitempty"`  // engine description of the line
}

var rejectActions = map[string]bool{"reject": true, "reject-200": true, "reject-img": true, "reject-dict": true, "reject-array": true, "reject-drop": true}

// quoteTok quotes a token for tokenize() when it is empty or contains whitespace (or starts with a quote).
func quoteTok(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t") && s[0] != '"' && s[0] != '\'' {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func quoteKV(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

// LineFromForm builds the canonical line and validates it with the engine parser.
func LineFromForm(f RewriteForm) RewriteForm {
	f.Error, f.Desc = "", ""
	p := strings.TrimSpace(f.Pattern)
	if f.Type != "raw" && p == "" {
		f.Error = "请填写 URL 正则"
		return f
	}
	if strings.ContainsAny(p, " \t") {
		f.Error = "URL 正则不能包含空格（用 \\s 或 %20）"
		return f
	}
	phase := f.Phase
	if phase != "response" {
		phase = "request"
	}
	switch f.Type {
	case "reject":
		a := strings.ToLower(f.Action)
		if !rejectActions[a] {
			a = "reject"
		}
		f.Line = p + " - " + a
	case "redirect":
		a := f.Action
		if a != "307" {
			a = "302"
		}
		t := strings.TrimSpace(f.Target)
		if t == "" || strings.ContainsAny(t, " \t") {
			f.Error = "请填写跳转地址（不能有空格，可用 $1 引用分组）"
			return f
		}
		f.Line = p + " " + t + " " + a
	case "header":
		name := strings.TrimSpace(f.HeaderName)
		if name == "" || strings.ContainsAny(name, " \t:") {
			f.Error = "请填写头名（不含空格和冒号）"
			return f
		}
		switch f.HeaderOp {
		case "del":
			f.Line = fmt.Sprintf("http-%s %s header-del %s", phase, p, name)
		case "replace", "add":
			f.Line = fmt.Sprintf("http-%s %s header-%s %s %s", phase, p, f.HeaderOp, name, f.HeaderValue)
		case "replace-regex":
			if f.HeaderRegex == "" {
				f.Error = "请填写要替换的正则"
				return f
			}
			f.Line = fmt.Sprintf("http-%s %s header-replace-regex %s %s %s", phase, p, name, quoteTok(f.HeaderRegex), f.HeaderValue)
		default:
			f.Error = "未知的头部操作"
			return f
		}
		f.Line = strings.TrimRight(f.Line, " ")
	case "body":
		if f.Regex == "" {
			f.Error = "请填写要替换的正则"
			return f
		}
		f.Line = fmt.Sprintf("http-%s %s %s %s", phase, p, quoteTok(f.Regex), quoteTok(f.Replacement))
	case "maplocal":
		var b strings.Builder
		b.WriteString(p)
		dt := f.DataType
		switch dt {
		case "tiny-gif":
			b.WriteString(` data-type=tiny-gif`)
		case "file":
			if strings.TrimSpace(f.Data) == "" {
				f.Error = "请填写文件路径或 URL"
				return f
			}
			b.WriteString(" data=" + quoteKV(f.Data) + " data-type=file")
		case "base64":
			b.WriteString(" data=" + quoteKV(f.Data) + " data-type=base64")
		default:
			b.WriteString(" data=" + quoteKV(f.Data) + " data-type=text")
		}
		if f.Status > 0 && f.Status != 200 {
			b.WriteString(" status-code=" + strconv.Itoa(f.Status))
		}
		var hs []string
		if ct := strings.TrimSpace(f.ContentType); ct != "" {
			hs = append(hs, "Content-Type:"+ct)
		}
		for _, h := range strings.Split(f.Headers, "|") {
			if h = strings.TrimSpace(h); h != "" && strings.Contains(h, ":") {
				hs = append(hs, h)
			}
		}
		if len(hs) > 0 {
			b.WriteString(" header=" + quoteKV(strings.Join(hs, "|")))
		}
		f.Line = b.String()
	case "raw":
		f.Line = strings.TrimSpace(f.Line)
		if f.Line == "" {
			f.Error = "规则为空"
			return f
		}
	default:
		f.Error = "未知类型"
		return f
	}
	rs := &Ruleset{}
	rs.ParseLine(f.Line, "", "用户")
	switch {
	case len(rs.Errors) > 0:
		f.Error = rs.Errors[0]
	case len(rs.Rules) == 1:
		f.Desc = rs.Rules[0].Desc
	case len(rs.Hostnames) > 0 && f.Type == "raw":
		f.Desc = "MitM 主机名"
	case len(rs.CoreRules) > 0 && f.Type == "raw":
		f.Desc = "内核规则：" + rs.CoreRules[0]
	case len(rs.Tasks) > 0 && f.Type == "raw":
		f.Desc = "脚本任务"
	default:
		f.Error = "无法识别这条规则"
	}
	return f
}

// FormFromLine maps a stored line onto the form (Type "raw" when the rule does not fit a form).
func FormFromLine(line string) RewriteForm {
	raw := RewriteForm{Type: "raw", Line: strings.TrimSpace(line)}
	rs := &Ruleset{}
	rs.ParseLine(line, "", "用户")
	if len(rs.Errors) > 0 {
		raw.Error = rs.Errors[0]
		return raw
	}
	if len(rs.Rules) != 1 {
		return raw
	}
	r := rs.Rules[0]
	raw.Desc = r.Desc
	f := RewriteForm{Pattern: r.Pattern, Phase: r.Phase, Desc: r.Desc}
	switch r.Kind {
	case KindURL:
		switch {
		case rejectActions[r.Action]:
			f.Type, f.Action = "reject", r.Action
		case r.Action == "302" || r.Action == "307":
			f.Type, f.Action, f.Target = "redirect", r.Action, r.Target
		default:
			return raw
		}
	case KindHeader:
		if len(r.Headers) != 1 {
			return raw
		}
		h := r.Headers[0]
		f.Type, f.HeaderOp, f.HeaderName, f.HeaderValue, f.HeaderRegex = "header", h.Op, h.Name, h.Value, h.Regex
	case KindBody:
		if len(r.Body) != 1 {
			return raw
		}
		f.Type, f.Regex, f.Replacement = "body", r.Body[0].Regex, r.Body[0].Repl
	case KindMapLocal:
		f.Type, f.Data, f.DataType, f.Status = "maplocal", r.Data, r.DataType, r.Status
		switch f.DataType {
		case "text", "base64", "file", "tiny-gif":
		default:
			return raw
		}
		var extra []string
		keys := make([]string, 0, len(r.RespHeaders))
		for k := range r.RespHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.EqualFold(k, "content-type") {
				f.ContentType = r.RespHeaders[k]
			} else {
				extra = append(extra, k+":"+r.RespHeaders[k])
			}
		}
		f.Headers = strings.Join(extra, "|")
	default:
		return raw
	}
	f.Line = strings.TrimSpace(line)
	return f
}
