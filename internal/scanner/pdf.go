package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"image/png"
	"log/slog"
	"os"
	"strings"

	"codeberg.org/go-pdf/fpdf"
	"golang.org/x/image/tiff"

	"github.com/mzyy94/airscap/internal/vens"
	"github.com/mzyy94/airscap/ndlocr"
)

// WritePDF combines scanned pages (JPEG or TIFF) into a single PDF file.
// TIFF pages are converted to 1-bit paletted PNG before embedding.
func WritePDF(pages []vens.Page, dpi int, isBW bool, outputPath string) error {
	data, err := GeneratePDF(pages, dpi, isBW)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// GeneratePDF combines scanned pages (JPEG or TIFF) into a PDF in memory.
// TIFF pages are converted to 1-bit paletted PNG before embedding.
func GeneratePDF(pages []vens.Page, dpi int, isBW bool) ([]byte, error) {
	if len(pages) == 0 {
		return nil, fmt.Errorf("no pages to write")
	}
	if dpi <= 0 {
		dpi = 300
	}

	pdf := fpdf.New("P", "mm", "", "")
	pdf.SetAutoPageBreak(false, 0)

	for i, p := range pages {
		cfg, _, err := image.DecodeConfig(bytes.NewReader(p.JPEG))
		if err != nil {
			return nil, fmt.Errorf("decode page %d image config: %w", i+1, err)
		}

		// Use actual DPI embedded in the image data when available
		pageDPI := dpi
		if d := detectImageDPI(p.JPEG); d > 0 {
			pageDPI = d
		} else if p.PixelSize != nil && p.PixelSize.XRes > 0 {
			pageDPI = p.PixelSize.XRes
		}

		widthMM := float64(cfg.Width) / float64(pageDPI) * 25.4
		heightMM := float64(cfg.Height) / float64(pageDPI) * 25.4

		pdf.AddPageFormat("P", fpdf.SizeType{Wd: widthMM, Ht: heightMM})

		name := fmt.Sprintf("page%d", i)
		if isBW {
			img, err := tiff.Decode(bytes.NewReader(p.JPEG))
			if err != nil {
				return nil, fmt.Errorf("decode page %d TIFF: %w", i+1, err)
			}
			palImg := toBitonalPNG(img)
			var buf bytes.Buffer
			if err := png.Encode(&buf, palImg); err != nil {
				return nil, fmt.Errorf("encode page %d PNG: %w", i+1, err)
			}
			pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: "PNG"}, &buf)
		} else {
			pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: "JPEG"}, bytes.NewReader(p.JPEG))
		}
		pdf.ImageOptions(name, 0, 0, widthMM, heightMM, false, fpdf.ImageOptions{}, 0, "")
	}

	var out bytes.Buffer
	if err := pdf.Output(&out); err != nil {
		return nil, fmt.Errorf("generate PDF: %w", err)
	}
	return out.Bytes(), nil
}

// GenerateOCRPDF combines scanned pages into a searchable PDF with transparent text overlay.
// Each page is processed through the OCR engine to extract text blocks.
// If OCR fails for a page, the page is included without a text layer.
func GenerateOCRPDF(ctx context.Context, pages []vens.Page, dpi int, isBW bool, engine *ndlocr.Engine) ([]byte, error) {
	if len(pages) == 0 {
		return nil, fmt.Errorf("no pages to write")
	}
	if dpi <= 0 {
		dpi = 300
	}

	pdf := fpdf.New("P", "mm", "", "")
	pdf.SetAutoPageBreak(false, 0)
	pdf.AddUTF8FontFromBytes("ja", "", ndlocr.EmbeddedFont)

	for i, p := range pages {
		// Decode full image for OCR
		var img image.Image
		var err error
		if isBW {
			img, err = tiff.Decode(bytes.NewReader(p.JPEG))
		} else {
			img, _, err = image.Decode(bytes.NewReader(p.JPEG))
		}
		if err != nil {
			return nil, fmt.Errorf("decode page %d: %w", i+1, err)
		}

		bounds := img.Bounds()

		// Use actual DPI embedded in the image data when available
		pageDPI := dpi
		if d := detectImageDPI(p.JPEG); d > 0 {
			pageDPI = d
		} else if p.PixelSize != nil && p.PixelSize.XRes > 0 {
			pageDPI = p.PixelSize.XRes
		}

		pxToMM := 25.4 / float64(pageDPI)
		widthMM := float64(bounds.Dx()) * pxToMM
		heightMM := float64(bounds.Dy()) * pxToMM

		pdf.AddPageFormat("P", fpdf.SizeType{Wd: widthMM, Ht: heightMM})

		// Embed image
		name := fmt.Sprintf("page%d", i)
		if isBW {
			palImg := toBitonalPNG(img)
			var buf bytes.Buffer
			if err := png.Encode(&buf, palImg); err != nil {
				return nil, fmt.Errorf("encode page %d PNG: %w", i+1, err)
			}
			pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: "PNG"}, &buf)
		} else {
			pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: "JPEG"}, bytes.NewReader(p.JPEG))
		}
		pdf.ImageOptions(name, 0, 0, widthMM, heightMM, false, fpdf.ImageOptions{}, 0, "")

		// OCR: recognize text and overlay
		blocks, err := engine.Recognize(ctx, img)
		if err != nil {
			slog.Warn("OCR failed for page, skipping text layer", "page", i+1, "err", err)
			continue
		}
		overlayOCRText(pdf, blocks, pxToMM)
	}

	var out bytes.Buffer
	if err := pdf.Output(&out); err != nil {
		return nil, fmt.Errorf("generate PDF: %w", err)
	}
	return out.Bytes(), nil
}

// overlayOCRText renders transparent text blocks onto the current PDF page.
// pxToMM converts pixel coordinates from OCR bounding boxes to mm.
func overlayOCRText(pdf *fpdf.Fpdf, blocks []ndlocr.TextBlock, pxToMM float64) {
	const mmToPt = 72.0 / 25.4

	pdf.SetAlpha(0.0, "Normal")
	pdf.SetTextColor(0, 0, 0)

	for _, b := range blocks {
		x1 := float64(b.BoundingBox[0][0]) * pxToMM
		y1 := float64(b.BoundingBox[0][1]) * pxToMM
		x2 := float64(b.BoundingBox[2][0]) * pxToMM
		y2 := float64(b.BoundingBox[2][1]) * pxToMM
		boxW := x2 - x1
		boxH := y2 - y1

		if boxW <= 0 || boxH <= 0 || b.Text == "" {
			continue
		}

		isVertical := strings.HasSuffix(b.Category, "vertical")
		runes := []rune(b.Text)
		nChars := len(runes)
		if nChars == 0 {
			continue
		}

		if isVertical {
			// Vertical: font size fits box width, chars spaced over box height
			fontMM := boxW
			charH := boxH / float64(nChars)
			if charH < fontMM {
				fontMM = charH
			}
			if fontMM <= 0 {
				fontMM = 0.1
			}
			pdf.SetFont("ja", "", fontMM*mmToPt)
			cx := x1 + (boxW-fontMM)/2
			for j, r := range runes {
				cy := y1 + float64(j)*charH + fontMM
				pdf.Text(cx, cy, string(r))
			}
		} else {
			// Horizontal: font size = box height, scaled to fit box width
			fontMM := boxH
			if fontMM <= 0 {
				fontMM = 0.1
			}
			pdf.SetFont("ja", "", fontMM*mmToPt)
			sw := pdf.GetStringWidth(b.Text) // returns mm
			if sw > 0 {
				fontMM *= boxW / sw
				pdf.SetFont("ja", "", fontMM*mmToPt)
			}
			pdf.Text(x1, y1+fontMM, b.Text)
		}
	}

	pdf.SetAlpha(1.0, "Normal")
}

// detectImageDPI extracts the X resolution (DPI) from image data.
// Supports TIFF (IFD XResolution tag) and JPEG (JFIF APP0 density).
// Returns 0 if the DPI cannot be determined.
func detectImageDPI(data []byte) int {
	if len(data) < 8 {
		return 0
	}
	// TIFF: starts with "II" (little-endian) or "MM" (big-endian)
	if (data[0] == 'I' && data[1] == 'I') || (data[0] == 'M' && data[1] == 'M') {
		return detectTIFFDPI(data)
	}
	// JPEG: starts with FF D8
	if data[0] == 0xFF && data[1] == 0xD8 {
		return detectJPEGDPI(data)
	}
	return 0
}

func detectTIFFDPI(data []byte) int {
	var bo binary.ByteOrder
	if data[0] == 'I' {
		bo = binary.LittleEndian
	} else {
		bo = binary.BigEndian
	}
	if bo.Uint16(data[2:4]) != 42 {
		return 0
	}
	ifdOff := int(bo.Uint32(data[4:8]))
	if ifdOff+2 > len(data) {
		return 0
	}
	n := int(bo.Uint16(data[ifdOff : ifdOff+2]))
	for i := range n {
		off := ifdOff + 2 + i*12
		if off+12 > len(data) {
			break
		}
		tag := bo.Uint16(data[off : off+2])
		if tag == 282 { // XResolution (RATIONAL = num/den)
			valOff := int(bo.Uint32(data[off+8 : off+12]))
			if valOff+8 > len(data) {
				return 0
			}
			num := bo.Uint32(data[valOff : valOff+4])
			den := bo.Uint32(data[valOff+4 : valOff+8])
			if den == 0 {
				return 0
			}
			return int(num / den)
		}
	}
	return 0
}

func detectJPEGDPI(data []byte) int {
	i := 2
	for i+4 < len(data) {
		if data[i] != 0xFF {
			break
		}
		marker := data[i+1]
		segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if marker == 0xE0 && segLen >= 14 { // APP0 (JFIF)
			seg := data[i+4:]
			if len(seg) >= 10 && string(seg[0:5]) == "JFIF\x00" {
				units := seg[7]
				xd := int(binary.BigEndian.Uint16(seg[8:10]))
				if units == 1 { // dots per inch
					return xd
				}
				if units == 2 { // dots per cm
					return int(float64(xd) * 2.54)
				}
			}
		}
		i += 2 + segLen
	}
	return 0
}

// toBitonalPNG converts an image to a 1-bit paletted image (black & white).
func toBitonalPNG(img image.Image) *image.Paletted {
	bounds := img.Bounds()
	palette := color.Palette{color.White, color.Black}
	dst := image.NewPaletted(bounds, palette)

	// Fast path: tiff.Decode returns *image.Gray for bilevel TIFF
	if gray, ok := img.(*image.Gray); ok {
		w := bounds.Dx()
		for y := range bounds.Dy() {
			srcRow := gray.Pix[y*gray.Stride : y*gray.Stride+w]
			dstRow := dst.Pix[y*dst.Stride : y*dst.Stride+w]
			for x, v := range srcRow {
				if v < 128 {
					dstRow[x] = 1 // black
				}
			}
		}
		return dst
	}

	// Fallback for other image types
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, _, _, _ := img.At(x, y).RGBA()
			if r < 0x8000 {
				dst.SetColorIndex(x, y, 1)
			}
		}
	}
	return dst
}
