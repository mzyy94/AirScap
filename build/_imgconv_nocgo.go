//go:build !cgo

package imgconv

import (
	"errors"
	"image/color"
	"io"
)

var errNoCGO = errors.New("imgconv: JPEG/PNG support requires CGO (libjpeg/libpng)")

func NewJPEGReader(input io.Reader) (Decoder, error) {
	return nil, errNoCGO
}

func NewJPEGWriter(output io.Writer, wid, hei int, model color.Model, quality int) (Encoder, error) {
	return nil, errNoCGO
}

func NewPNGReader(input io.Reader) (Decoder, error) {
	return nil, errNoCGO
}

func NewPNGWriter(output io.Writer, wid, hei int, model color.Model) (Encoder, error) {
	return nil, errNoCGO
}
