package mitm

import (
	"errors"
	"io"
	"reflect"

	"github.com/andybalholm/brotli"
)

// errBrotliTruncated: the br stream ended before its last meta-block. andybalholm/brotli v1.1.1 reports a clean
// io.EOF whenever the input runs out right after a Read that produced output (its Read returns n, nil while
// the decoder still needs input; the next Read finds the source empty and passes the source's io.EOF through),
// so a body cut mid-way decoded "successfully" to a prefix and scripts / rewrites ran on it — the client got
// a truncated response re-sent with a fresh Content-Length.
var errBrotliTruncated = errors.New("brotli: truncated stream")

// brotliStateDone is the decoder's final state (brotli v1.1.1 state.go: stateDone, the 25th state). The package
// exports no way to ask whether the stream ended, so strictBrotli reads the Reader's unexported state field
// through reflect (read only). TestBrotliStateFieldPinned fails when an upgrade moves it; until then a
// missing field makes the check lenient again (the old behaviour), never a false error.
const brotliStateDone = 24

var brotliStateField = func() int {
	f, ok := reflect.TypeOf(brotli.Reader{}).FieldByName("state")
	if !ok || f.Type.Kind() != reflect.Int || len(f.Index) != 1 {
		return -1
	}
	return f.Index[0]
}()

// brotliFinished reports whether br decoded a complete stream (true when that cannot be told).
func brotliFinished(br *brotli.Reader) bool {
	if brotliStateField < 0 {
		return true
	}
	return reflect.ValueOf(br).Elem().Field(brotliStateField).Int() == brotliStateDone
}

// strictBrotli is a brotli reader that reports io.EOF only for a complete stream and errBrotliTruncated for a
// stream the input ended inside of. An empty input (no stream at all) stays an empty body.
type strictBrotli struct {
	br  *brotli.Reader
	src countSource
	err error // sticky once the end was reached
}

type countSource struct {
	r io.Reader
	n int64
}

func (c *countSource) Read(b []byte) (int, error) {
	k, err := c.r.Read(b)
	c.n += int64(k)
	return k, err
}

func newStrictBrotli(r io.Reader) *strictBrotli {
	s := &strictBrotli{}
	s.src.r = r
	s.br = brotli.NewReader(&s.src)
	return s
}

// Reset starts over on r, keeping the decoder's buffers (brotli's ring buffer, up to 4 MB).
func (s *strictBrotli) Reset(r io.Reader) error {
	s.src = countSource{r: r}
	s.err = nil
	return s.br.Reset(&s.src)
}

func (s *strictBrotli) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.br.Read(p)
	switch {
	case err == io.EOF:
		if s.src.n > 0 && !brotliFinished(s.br) {
			err = errBrotliTruncated
		}
		s.err = err
	case err == io.ErrUnexpectedEOF:
		err = errBrotliTruncated
		s.err = err
	}
	return n, err
}
