package mitm

import (
	"testing"

	"github.com/dop251/goja"
)

// 喜马拉雅 (ximalaya.js) decrypts the paid-track "ep" with Uint8Array.from(binaryString, c => c.charCodeAt(0)).
// Upstream goja rejected a primitive string source ("Value is not an object"), so the script fell back and
// the app showed the VIP / 喜点 prompt.
func TestGojaTypedArrayFromString(t *testing.T) {
	vm := goja.New()
	v, err := vm.RunString(`
		var a = Uint8Array.from("A\u00ff\u0080", function (c) { return c.charCodeAt(0); });
		var b = Uint8Array.from("12");
		a.length === 3 && a[0] === 65 && a[1] === 255 && a[2] === 128 && b[0] === 1 && b[1] === 2;`)
	if err != nil || !v.ToBoolean() {
		t.Fatalf("Uint8Array.from(string): %v %v", v, err)
	}
	if _, err := vm.RunString("Uint8Array.from(null)"); err == nil {
		t.Fatal("null source must throw")
	}
}
