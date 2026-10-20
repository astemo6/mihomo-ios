package mitm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/metrics"
	"time"
)

// review6: memory and fidelity guards for JSON body rules (jq / Loon response-body-json-*).

// jsonBodyLimit caps bodies handed to the JSON rules. Decoding into a Go value tree costs ~20× the
// body in heap (measured: a 2 MB JSON array → +40 MB for jq or a json-del), so a MaxBody JSON body
// alone could exceed the extension's 26 MB GOMEMLIMIT.
const jsonBodyLimit = 1 << 20

// jsonHeapPerByte is the estimated peak heap per body byte of a JSON rule (decode + edit + encode).
const jsonHeapPerByte = 22

var jsonHeapNow = func() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return s[0].Value.Uint64()
}

// jsonBodyFits refuses a JSON rule whose decode would not fit: bodies over jsonBodyLimit, or when the
// current heap plus the estimate passes 90 % of GOMEMLIMIT (no limit set → only the size cap).
func jsonBodyFits(n int) error {
	if n > jsonBodyLimit {
		return fmt.Errorf("JSON 改写只处理 %d KB 以内的内容（%d KB），跳过", jsonBodyLimit>>10, n>>10)
	}
	limit := memGuardLimit()
	if limit <= 0 || limit >= 1<<40 {
		return nil
	}
	if jsonHeapNow()+uint64(n)*jsonHeapPerByte > uint64(limit)/10*9 {
		return errors.New("内存紧张，跳过 JSON 改写")
	}
	return nil
}

// decodeJSONNumber decodes one JSON value keeping numbers as json.Number: 64-bit IDs
// (1234567890123456789) used to come back as 1.2345678901234568e+18 after any jq / json-del rule.
// gojq accepts json.Number natively.
func decodeJSONNumber(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// encodeJSON is json.Marshal without HTML escaping (json.Marshal turned "<a href>&" into \u003c… in
// every rewritten body), and without the encoder's trailing newline.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// readSized reads a body of up to limit bytes (more → limit+1 bytes, which callers treat as too big).
// review6 OPT-4: with a known Content-Length it reads into one exact allocation; io.ReadAll's doubling
// left ~1–2× the body in garbage per download.
func readSized(r io.Reader, contentLength int64, limit int) ([]byte, error) {
	if contentLength < 0 || contentLength > int64(limit) {
		return io.ReadAll(io.LimitReader(r, int64(limit)+1))
	}
	b := make([]byte, contentLength, contentLength+1)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	var one [1]byte
	if n, _ := r.Read(one[:]); n > 0 { // longer than announced: read the rest the slow way
		rest, err := io.ReadAll(io.LimitReader(r, int64(limit)+1-int64(len(b))-1))
		if err != nil {
			return nil, err
		}
		b = append(append(b, one[0]), rest...)
	}
	return b, nil
}

// sniPeekTimeout bounds reading the ClientHello for SNI when CONNECT carried an IP (review6 P2-5).
var sniPeekTimeout = 10 * time.Second
