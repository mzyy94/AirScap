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
		// Bilinear chroma upsampling + libjpeg-compatible YCbCr -> RGB.
		// Go's image/jpeg returns chroma planes at sub-sampled resolution and
		// COffset uses nearest-neighbor lookup, which differs from libjpeg /
		// PIL.Image.convert("RGB") (centered MPEG-1-style sampling). To match
		// libjpeg exactly: bilinearly upsample chroma in float, round to byte
		// (mirroring libjpeg's per-byte chroma plane after upsampling), then
		// apply stdlib's fixed-point YCbCr -> RGB conversion (which uses the
		// same 0x10101 / table-based math libjpeg does).
		hxRatio, hyRatio := chromaSubsampleRatio(src.SubsampleRatio)
		planeStride := src.CStride
		planeW := planeStride
		planeH := 0
		if planeStride > 0 {
			planeH = len(src.Cb) / planeStride
		}
		ymin := bounds.Min.Y - src.Rect.Min.Y
		xmin := bounds.Min.X - src.Rect.Min.X
		clipByte := func(v int32) float32 {
			if v < 0 {
				return 0
			}
			if v > 255 {
				return 255
			}
			return float32(v)
		}
		for y := 0; y < h; y++ {
			yi := (y+ymin)*src.YStride + xmin
			dstOff := y * w * 3
			for x := 0; x < w; x++ {
				yy := int32(src.Y[yi])
				cb := int32(roundByteF(sampleChromaBilinearF(src.Cb, planeStride, planeW, planeH, x+xmin, y+ymin, hxRatio, hyRatio))) - 128
				cr := int32(roundByteF(sampleChromaBilinearF(src.Cr, planeStride, planeW, planeH, x+xmin, y+ymin, hxRatio, hyRatio))) - 128
				// libjpeg-style YCbCr -> RGB: chroma table values are
				// floor((coef * (Chroma - 128) + 32768) / 65536), then added to Y.
				// Floor division semantics (asr16) matter for negative values.
				rOff := asr16(91881*cr + 32768)
				gOff := asr16(-22554*cb - 46802*cr + 32768)
				bOff := asr16(116130*cb + 32768)
				data[dstOff+0] = clipByte(yy + rOff)
				data[dstOff+1] = clipByte(yy + gOff)
				data[dstOff+2] = clipByte(yy + bOff)
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

// chromaSubsampleRatio returns the horizontal and vertical chroma subsample
// ratios (1, 2, or 4) for a given image.YCbCrSubsampleRatio.
func chromaSubsampleRatio(r image.YCbCrSubsampleRatio) (hx, hy int) {
	switch r {
	case image.YCbCrSubsampleRatio444:
		return 1, 1
	case image.YCbCrSubsampleRatio422:
		return 2, 1
	case image.YCbCrSubsampleRatio420:
		return 2, 2
	case image.YCbCrSubsampleRatio440:
		return 1, 2
	case image.YCbCrSubsampleRatio411:
		return 4, 1
	case image.YCbCrSubsampleRatio410:
		return 4, 2
	}
	return 1, 1
}

// asr16 returns v arithmetically right-shifted by 16 (i.e. floor(v / 65536)).
// Go's >> on signed int32 is already an arithmetic shift (floor for negatives),
// so this is just a documented wrapper for clarity.
func asr16(v int32) int32 { return v >> 16 }

// roundByteF rounds a float64 to the nearest byte value in [0, 255].
func roundByteF(v float64) byte {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return byte(v + 0.5)
}

// sampleChromaBilinearF returns the bilinearly upsampled chroma value as a
// float64 at the given full-resolution Y pixel coordinate. Mirrors libjpeg /
// PIL behavior: chroma samples are taken to be centered between Y pixels
// (MPEG-1 siting), so chroma sample index c covers Y positions
// [c*ratio, (c+1)*ratio - 1] and is centered at Y position c*ratio + ratio/2 - 0.5.
func sampleChromaBilinearF(plane []byte, stride, planeW, planeH, x, y, hxRatio, hyRatio int) float64 {
	if planeW <= 0 || planeH <= 0 {
		return 128
	}
	if hxRatio == 1 && hyRatio == 1 {
		return float64(plane[y*stride+x])
	}
	// Fractional chroma coordinate corresponding to (x, y).
	fx := (float64(x)+0.5)/float64(hxRatio) - 0.5
	fy := (float64(y)+0.5)/float64(hyRatio) - 0.5
	x0 := int(fx)
	if fx < 0 && fx != float64(x0) {
		x0--
	}
	y0 := int(fy)
	if fy < 0 && fy != float64(y0) {
		y0--
	}
	dx := fx - float64(x0)
	dy := fy - float64(y0)
	x1 := x0 + 1
	y1 := y0 + 1
	if x0 < 0 {
		x0 = 0
	}
	if y0 < 0 {
		y0 = 0
	}
	if x1 >= planeW {
		x1 = planeW - 1
	}
	if y1 >= planeH {
		y1 = planeH - 1
	}
	if x0 >= planeW {
		x0 = planeW - 1
	}
	if y0 >= planeH {
		y0 = planeH - 1
	}
	a := float64(plane[y0*stride+x0])
	b := float64(plane[y0*stride+x1])
	c := float64(plane[y1*stride+x0])
	d := float64(plane[y1*stride+x1])
	return a*(1-dx)*(1-dy) + b*dx*(1-dy) + c*(1-dx)*dy + d*dx*dy
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
