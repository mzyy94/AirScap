package ndlocr

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	_ "golang.org/x/image/bmp"
	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/tiff"
)

// LoadImage reads an image file and returns it as image.Image.
func LoadImage(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open image %s: %w", path, err)
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image %s: %w", path, err)
	}
	return img, nil
}

// ImageToRGB converts an image.Image to a flat []float32 in HWC RGB order with values 0-255.
// Uses type assertions to access pixel buffers directly for common image types,
// avoiding per-pixel interface dispatch overhead.
func ImageToRGB(img image.Image) ([]float32, int, int) {
	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	data := make([]float32, h*w*3)

	switch src := img.(type) {
	case *image.NRGBA:
		for y := 0; y < h; y++ {
			srcOff := (y+bounds.Min.Y-src.Rect.Min.Y)*src.Stride + (bounds.Min.X-src.Rect.Min.X)*4
			dstOff := y * w * 3
			for x := 0; x < w; x++ {
				data[dstOff+0] = float32(src.Pix[srcOff+0])
				data[dstOff+1] = float32(src.Pix[srcOff+1])
				data[dstOff+2] = float32(src.Pix[srcOff+2])
				srcOff += 4
				dstOff += 3
			}
		}
	case *image.RGBA:
		for y := 0; y < h; y++ {
			srcOff := (y+bounds.Min.Y-src.Rect.Min.Y)*src.Stride + (bounds.Min.X-src.Rect.Min.X)*4
			dstOff := y * w * 3
			for x := 0; x < w; x++ {
				a := src.Pix[srcOff+3]
				if a == 255 {
					data[dstOff+0] = float32(src.Pix[srcOff+0])
					data[dstOff+1] = float32(src.Pix[srcOff+1])
					data[dstOff+2] = float32(src.Pix[srcOff+2])
				} else if a == 0 {
					// data is already zeroed
				} else {
					// Un-premultiply
					fa := float32(a)
					data[dstOff+0] = float32(src.Pix[srcOff+0]) * 255.0 / fa
					data[dstOff+1] = float32(src.Pix[srcOff+1]) * 255.0 / fa
					data[dstOff+2] = float32(src.Pix[srcOff+2]) * 255.0 / fa
				}
				srcOff += 4
				dstOff += 3
			}
		}
	case *image.YCbCr:
		for y := 0; y < h; y++ {
			yi := (y+bounds.Min.Y-src.Rect.Min.Y)*src.YStride + (bounds.Min.X - src.Rect.Min.X)
			dstOff := y * w * 3
			for x := 0; x < w; x++ {
				ci := src.COffset(bounds.Min.X+x, bounds.Min.Y+y)
				yy := int32(src.Y[yi])
				cb := int32(src.Cb[ci]) - 128
				cr := int32(src.Cr[ci]) - 128
				r := yy + 91881*cr/65536
				g := yy - 22554*cb/65536 - 46802*cr/65536
				b := yy + 116130*cb/65536
				if r < 0 {
					r = 0
				} else if r > 255 {
					r = 255
				}
				if g < 0 {
					g = 0
				} else if g > 255 {
					g = 255
				}
				if b < 0 {
					b = 0
				} else if b > 255 {
					b = 255
				}
				data[dstOff+0] = float32(r)
				data[dstOff+1] = float32(g)
				data[dstOff+2] = float32(b)
				yi++
				dstOff += 3
			}
		}
	case *image.Gray:
		for y := 0; y < h; y++ {
			srcOff := (y+bounds.Min.Y-src.Rect.Min.Y)*src.Stride + (bounds.Min.X - src.Rect.Min.X)
			dstOff := y * w * 3
			for x := 0; x < w; x++ {
				v := float32(src.Pix[srcOff])
				data[dstOff+0] = v
				data[dstOff+1] = v
				data[dstOff+2] = v
				srcOff++
				dstOff += 3
			}
		}
	default:
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				r, g, b, _ := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
				idx := (y*w + x) * 3
				data[idx+0] = float32(r >> 8)
				data[idx+1] = float32(g >> 8)
				data[idx+2] = float32(b >> 8)
			}
		}
	}

	return data, h, w
}

// PadToSquare pads the HWC image data to a square by adding zeros.
func PadToSquare(data []float32, h, w int) ([]float32, int) {
	maxDim := h
	if w > maxDim {
		maxDim = w
	}
	if h == maxDim && w == maxDim {
		return data, maxDim
	}
	padded := make([]float32, maxDim*maxDim*3)
	for y := 0; y < h; y++ {
		srcOff := y * w * 3
		dstOff := y * maxDim * 3
		copy(padded[dstOff:dstOff+w*3], data[srcOff:srcOff+w*3])
	}
	return padded, maxDim
}

// resizeImage resizes an image.Image to the target size using the given interpolator.
func resizeImage(img image.Image, targetW, targetH int, interp xdraw.Interpolator) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, targetW, targetH))
	interp.Scale(dst, dst.Bounds(), img, img.Bounds(), xdraw.Over, nil)
	return dst
}

// ResizeHWC resizes HWC float32 data by creating a temporary image, resizing, then converting back.
func ResizeHWC(data []float32, srcH, srcW, dstH, dstW int, interp xdraw.Interpolator) []float32 {
	img := image.NewNRGBA(image.Rect(0, 0, srcW, srcH))
	for y := 0; y < srcH; y++ {
		for x := 0; x < srcW; x++ {
			idx := (y*srcW + x) * 3
			img.SetNRGBA(x, y, color.NRGBA{
				R: uint8(data[idx+0]),
				G: uint8(data[idx+1]),
				B: uint8(data[idx+2]),
				A: 255,
			})
		}
	}
	resized := resizeImage(img, dstW, dstH, interp)
	result := make([]float32, dstH*dstW*3)
	for y := 0; y < dstH; y++ {
		for x := 0; x < dstW; x++ {
			c := resized.NRGBAAt(x, y)
			idx := (y*dstW + x) * 3
			result[idx+0] = float32(c.R)
			result[idx+1] = float32(c.G)
			result[idx+2] = float32(c.B)
		}
	}
	return result
}

// PreprocessDEIM performs DEIM-specific preprocessing:
// 1. Normalize to 0-1, 2. ImageNet mean/std normalization, 3. HWC -> NCHW
func PreprocessDEIM(data []float32, h, w int) []float32 {
	mean := [3]float32{0.485, 0.456, 0.406}
	std := [3]float32{0.229, 0.224, 0.225}
	nchw := make([]float32, 1*3*h*w)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			srcIdx := (y*w + x) * 3
			for c := 0; c < 3; c++ {
				val := data[srcIdx+c] / 255.0
				val = (val - mean[c]) / std[c]
				nchw[c*h*w+y*w+x] = val
			}
		}
	}
	return nchw
}

// PreprocessPARSeq performs PARSeq-specific preprocessing:
// 1. Resize to target dimensions
// 2. BGR conversion + normalize to [-1, 1]
// 3. HWC -> NCHW
// Note: Rotation for vertical text is handled by PARSEQ.Read() before calling this function.
func PreprocessPARSeq(data []float32, h, w, targetH, targetW int) []float32 {
	resized := ResizeHWC(data, h, w, targetH, targetW, xdraw.BiLinear)

	nchw := make([]float32, 1*3*targetH*targetW)
	for y := 0; y < targetH; y++ {
		for x := 0; x < targetW; x++ {
			srcIdx := (y*targetW + x) * 3
			r := resized[srcIdx+0]
			g := resized[srcIdx+1]
			b := resized[srcIdx+2]
			// BGR order and normalize to [-1, 1]
			nchw[0*targetH*targetW+y*targetW+x] = 2.0*(b/255.0) - 1.0
			nchw[1*targetH*targetW+y*targetW+x] = 2.0*(g/255.0) - 1.0
			nchw[2*targetH*targetW+y*targetW+x] = 2.0*(r/255.0) - 1.0
		}
	}
	return nchw
}

// CropRegion extracts a rectangular region from HWC image data.
func CropRegion(data []float32, imgW, xmin, ymin, cropW, cropH int) []float32 {
	crop := make([]float32, cropH*cropW*3)
	for y := 0; y < cropH; y++ {
		srcOff := ((ymin+y)*imgW + xmin) * 3
		dstOff := y * cropW * 3
		copy(crop[dstOff:dstOff+cropW*3], data[srcOff:srcOff+cropW*3])
	}
	return crop
}

// DrawDetections draws bounding boxes on an image and saves it.
func DrawDetections(img image.Image, detections []Detection, outputPath string) error {
	bounds := img.Bounds()
	canvas := image.NewRGBA(bounds)
	draw.Draw(canvas, bounds, img, bounds.Min, draw.Src)

	colorList := [][3]uint8{
		{0, 0, 0}, {255, 0, 0}, {0, 0, 142}, {0, 0, 230}, {106, 0, 228},
		{0, 60, 100}, {0, 80, 100}, {0, 0, 70}, {0, 0, 192}, {250, 170, 30},
		{100, 170, 30}, {220, 220, 0}, {175, 116, 175}, {250, 0, 30}, {165, 42, 42},
		{255, 77, 255}, {255, 0, 0},
	}

	for _, det := range detections {
		x1, y1, x2, y2 := int(det.Box[0]), int(det.Box[1]), int(det.Box[2]), int(det.Box[3])
		ci := det.ClassIndex
		if ci < 0 || ci >= len(colorList) {
			ci = 0
		}
		c := color.RGBA{R: colorList[ci][0], G: colorList[ci][1], B: colorList[ci][2], A: 255}
		drawRect(canvas, x1, y1, x2, y2, c, 2)
	}

	ext := strings.ToLower(filepath.Ext(outputPath))
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if ext == ".png" {
		return png.Encode(f, canvas)
	}
	return jpeg.Encode(f, canvas, &jpeg.Options{Quality: 95})
}

func drawRect(img *image.RGBA, x1, y1, x2, y2 int, c color.RGBA, width int) {
	bounds := img.Bounds()
	clamp := func(v, lo, hi int) int {
		if v < lo {
			return lo
		}
		if v > hi {
			return hi
		}
		return v
	}
	x1 = clamp(x1, bounds.Min.X, bounds.Max.X-1)
	y1 = clamp(y1, bounds.Min.Y, bounds.Max.Y-1)
	x2 = clamp(x2, bounds.Min.X, bounds.Max.X-1)
	y2 = clamp(y2, bounds.Min.Y, bounds.Max.Y-1)

	for w := 0; w < width; w++ {
		for x := x1; x <= x2; x++ {
			if y1+w <= bounds.Max.Y-1 {
				img.SetRGBA(x, y1+w, c)
			}
			if y2-w >= bounds.Min.Y {
				img.SetRGBA(x, y2-w, c)
			}
		}
		for y := y1; y <= y2; y++ {
			if x1+w <= bounds.Max.X-1 {
				img.SetRGBA(x1+w, y, c)
			}
			if x2-w >= bounds.Min.X {
				img.SetRGBA(x2-w, y, c)
			}
		}
	}
}

// Rotate90CCW rotates HWC image data 90 degrees counter-clockwise.
// This matches PIL Image.ROTATE_90 (which is CCW).
func Rotate90CCW(data []float32, h, w int) ([]float32, int, int) {
	newH := w
	newW := h
	rotated := make([]float32, newH*newW*3)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			srcIdx := (y*w + x) * 3
			newX := y
			newY := w - 1 - x
			dstIdx := (newY*newW + newX) * 3
			rotated[dstIdx+0] = data[srcIdx+0]
			rotated[dstIdx+1] = data[srcIdx+1]
			rotated[dstIdx+2] = data[srcIdx+2]
		}
	}
	return rotated, newH, newW
}
