package mitm

import "testing"

// The native front's upstream TLS follows the engine's skip-cert-verify (bridge MitmSkipCertVerify →
// UpstreamTarget.skipVerify); before 2026-10-24 it always used system trust, so origins the Go path accepted
// failed natively.
func TestEngineSkipCertVerifyExposed(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, CaptureBodies: noCapture()}
	h := newHarness(t, cfg, nil) // the harness reloads with SkipCertVerify = true
	if !h.e.SkipCertVerify() {
		t.Fatal("skip-cert-verify on: SkipCertVerify() = false")
	}
	off := &Config{Enabled: true, MitM: true, CaptureBodies: noCapture()}
	h.e.Reload(off, Build(h.home, off))
	if h.e.SkipCertVerify() {
		t.Fatal("skip-cert-verify off: SkipCertVerify() = true")
	}
}
