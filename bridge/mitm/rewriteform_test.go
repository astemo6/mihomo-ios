package mitm

import "testing"

func TestRewriteFormRoundTrip(t *testing.T) {
	cases := []RewriteForm{
		{Type: "reject", Pattern: `^https?://ad\.example\.com/v1`, Action: "reject-dict"},
		{Type: "redirect", Pattern: `^http://a\.com/(.*)`, Target: "https://b.com/$1", Action: "307"},
		{Type: "header", Pattern: `^https?://api\.x\.com`, Phase: "request", HeaderOp: "add", HeaderName: "X-Token", HeaderValue: "a b"},
		{Type: "header", Pattern: `^https?://api\.x\.com`, Phase: "response", HeaderOp: "del", HeaderName: "Set-Cookie"},
		{Type: "header", Pattern: `^https?://api\.x\.com`, Phase: "request", HeaderOp: "replace-regex", HeaderName: "User-Agent", HeaderRegex: `iPhone OS \d+`, HeaderValue: "iPad"},
		{Type: "body", Pattern: `^https?://api\.x\.com/feed`, Phase: "response", Regex: `"ad":\s?true`, Replacement: `"ad": false`},
		{Type: "maplocal", Pattern: `^https?://x\.com/api`, Data: `{"ok":"yes"}`, DataType: "text", ContentType: "application/json", Status: 201, Headers: "X-A:1"},
		{Type: "maplocal", Pattern: `^https?://x\.com/pix`, DataType: "tiny-gif"},
	}
	for _, c := range cases {
		out := LineFromForm(c)
		if out.Error != "" || out.Desc == "" {
			t.Fatalf("%+v → %+v", c, out)
		}
		back := FormFromLine(out.Line)
		if back.Type != c.Type || back.Pattern != c.Pattern {
			t.Fatalf("round trip %q → %+v", out.Line, back)
		}
		switch c.Type {
		case "redirect":
			if back.Target != c.Target || back.Action != c.Action {
				t.Fatalf("redirect %+v", back)
			}
		case "header":
			if back.HeaderOp != c.HeaderOp || back.HeaderName != c.HeaderName || back.HeaderValue != c.HeaderValue || back.HeaderRegex != c.HeaderRegex || back.Phase != c.Phase {
				t.Fatalf("header %q %+v", out.Line, back)
			}
		case "body":
			if back.Regex != c.Regex || back.Replacement != c.Replacement || back.Phase != "response" {
				t.Fatalf("body %q %+v", out.Line, back)
			}
		case "maplocal":
			if back.Data != c.Data || back.DataType != c.DataType || back.ContentType != c.ContentType || back.Headers != c.Headers || (c.Status != 0 && back.Status != c.Status) {
				t.Fatalf("maplocal %q %+v", out.Line, back)
			}
		case "reject":
			if back.Action != c.Action {
				t.Fatalf("reject %+v", back)
			}
		}
	}
}

func TestRewriteFormValidationAndForeignSyntax(t *testing.T) {
	if f := LineFromForm(RewriteForm{Type: "reject", Pattern: `^https://a(`}); f.Error == "" {
		t.Fatal("bad regex accepted")
	}
	if f := LineFromForm(RewriteForm{Type: "redirect", Pattern: `^a`}); f.Error == "" {
		t.Fatal("missing target accepted")
	}
	if f := LineFromForm(RewriteForm{Type: "header", Pattern: `^a`, HeaderOp: "add"}); f.Error == "" {
		t.Fatal("missing header name accepted")
	}
	// QX line opens in the form.
	f := FormFromLine(`^https?:\/\/api\.example\.com\/ad url reject-dict`)
	if f.Type != "reject" || f.Action != "reject-dict" {
		t.Fatalf("qx %+v", f)
	}
	// Loon JSON ops do not fit a form → raw.
	if f := FormFromLine(`^https?://api\.example\.com/feed response-body-json-del data.ads`); f.Type != "raw" || f.Desc == "" {
		t.Fatalf("loon %+v", f)
	}
	if f := LineFromForm(RewriteForm{Type: "raw", Line: "hostname = a.com"}); f.Error != "" {
		t.Fatalf("raw hostname %+v", f)
	}
}
