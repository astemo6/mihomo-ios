package mitm

import "testing"

func TestCompileReJSIdentityEscape(t *testing.T) {
	re, err := compileRe(`https:\/\/bookapi\.ihuman\.com\/(v1\/get\_user\_info|v1\/get\_purchase\_list)`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := re.MatchString("https://bookapi.ihuman.com/v1/get_user_info"); !ok {
		t.Fatal("no match")
	}
	if got := dropJSIdentityEscapes(`a\\_b\_c`); got != `a\\_b_c` {
		t.Fatalf("got %q", got)
	}
}
