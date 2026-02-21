package scanner

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg"
	"image/png"

	"codeberg.org/go-pdf/fpdf"
	"golang.org/x/image/tiff"

	"github.com/mzyy94/airscap/internal/vens"
)

// WritePDF combines scanned pages (JPEG or TIFF) into a single PDF file.
// TIFF pages are converted to 1-bit paletted PNG before embedding.
func WritePDF(pages []vens.Page, dpi int, isBW bool, outputPath string) error {
	if len(pages) == 0 {
		return fmt.Errorf("no pages to write")
	}
	if dpi <= 0 {
		dpi = 300
	}

	pdf := fpdf.New("P", "mm", "", "")
	pdf.SetAutoPageBreak(false, 0)

	for i, p := range pages {
		cfg, _, err := image.DecodeConfig(bytes.NewReader(p.JPEG))
		if err != nil {
			return fmt.Errorf("decode page %d image config: %w", i+1, err)
		}

		widthMM := float64(cfg.Width) / float64(dpi) * 25.4
		heightMM := float64(cfg.Height) / float64(dpi) * 25.4

		pdf.AddPageFormat("P", fpdf.SizeType{Wd: widthMM, Ht: heightMM})

		name := fmt.Sprintf("page%d", i)
		if isBW {
			img, err := tiff.Decode(bytes.NewReader(p.JPEG))
			if err != nil {
				return fmt.Errorf("decode page %d TIFF: %w", i+1, err)
			}
			palImg := toBitonalPNG(img)
			var buf bytes.Buffer
			if err := png.Encode(&buf, palImg); err != nil {
				return fmt.Errorf("encode page %d PNG: %w", i+1, err)
			}
			pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: "PNG"}, &buf)
		} else {
			pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: "JPEG"}, bytes.NewReader(p.JPEG))
		}
		pdf.ImageOptions(name, 0, 0, widthMM, heightMM, false, fpdf.ImageOptions{}, 0, "")
	}

	return pdf.OutputFileAndClose(outputPath)
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
