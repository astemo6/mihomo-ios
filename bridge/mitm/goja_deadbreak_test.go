package mitm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// TestGojaDeadCodeBreak: goja patch 4 (third_party/goja PATCHED.md). A `break` inside constant-false
// dead code (`e: if(!1){ …; break }` in a switch case — obfuscator output, e.g. a Loon 喜马拉雅 plugin
// script) registered a pc of the throw-away dummy program on the real switch block; patching it
// overwrote a live instruction: 「Compiler bug: Unsupported instruction for binding: goja.jump」, or
// silently wrong code when the overwritten instruction was not a binding access.
func TestGojaDeadCodeBreak(t *testing.T) {
	for n := 0; n <= 16; n++ {
		src := fmt.Sprintf(`(function(o){ var y = 1, z = 2; function g(){ return y + z }
switch(o){ case 5: e: if(!1){ %s break } y = z + y; z = y + z; case 6: for(;;){ if(false){ %s continue } break } }
return g() })(5)`, strings.Repeat("x();", n), strings.Repeat("x();", n))
		vm := goja.New()
		v, err := vm.RunString(src)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if v.ToInteger() != 8 {
			t.Fatalf("n=%d: got %v, want 8", n, v)
		}
	}
}
