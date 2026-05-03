package ndlocr

import (
	"context"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	ort "github.com/shota3506/onnxruntime-purego/onnxruntime"
	"gopkg.in/yaml.v3"
)

// Config specifies the configuration for the OCR engine.
type Config struct {
	// ModelDir is the directory containing model/ and config/ subdirectories.
	ModelDir string

	// Device is the inference device: "cpu" or "cuda". Default: "cpu".
	Device string

	// RuntimePath is the path to the ONNX Runtime shared library.
	// If empty, the system standard paths are searched automatically.
	RuntimePath string
}

// TextBlock represents a recognized text region.
type TextBlock struct {
	Text        string
	BoundingBox [4][2]int // [topLeft, topRight, bottomRight, bottomLeft] (clockwise)
	Category    string
	Confidence  float32
}

// Engine is the OCR engine holding detection and recognition models.
type Engine struct {
	runtime *ort.Runtime
	env     *ort.Env

	detector *DEIM
	rec30    *PARSEQ
	rec50    *PARSEQ
	rec100   *PARSEQ
}

// RuntimeAvailable reports whether the ONNX Runtime shared library can be loaded.
// If runtimePath is empty, the system standard paths are searched automatically.
func RuntimeAvailable(runtimePath string) bool {
	rt, err := ort.NewRuntime(runtimePath, 23)
	if err != nil {
		return false
	}
	rt.Close()
	return true
}

// requiredFiles lists the model and config files needed for OCR, relative to ModelDir.
var requiredFiles = []string{
	"model/deim-s-1024x1024.onnx",
	"model/parseq-ndl-24x256-30-tiny-189epoch-tegaki3-r8data-202604.onnx",
	"model/parseq-ndl-24x384-50-tiny-300epoch-tegaki3-r8data-202604.onnx",
	"model/parseq-ndl-24x768-100-tiny-153epoch-tegaki3-r8data-202604.onnx",
	"config/ndl.yaml",
	"config/NDLmoji.yaml",
}

// CheckModels checks whether all required model and config files exist under modelDir.
// Returns nil if all files are present, or an error listing missing files.
func CheckModels(modelDir string) error {
	var missing []string
	for _, rel := range requiredFiles {
		p := filepath.Join(modelDir, rel)
		if _, err := os.Stat(p); err != nil {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing model files: %s", strings.Join(missing, ", "))
	}
	return nil
}

// NewEngine creates a new OCR engine by loading all models from the given config.
func NewEngine(cfg Config) (*Engine, error) {
	runtime, err := ort.NewRuntime(cfg.RuntimePath, 23)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ONNX Runtime: %w", err)
	}

	env, err := runtime.NewEnv("ndlocr", ort.LoggingLevelWarning)
	if err != nil {
		runtime.Close()
		return nil, fmt.Errorf("failed to create ONNX environment: %w", err)
	}

	device := cfg.Device
	if device == "" {
		device = "cpu"
	}

	modelDir := filepath.Join(cfg.ModelDir, "model")
	configDir := filepath.Join(cfg.ModelDir, "config")

	detWeights := filepath.Join(modelDir, "deim-s-1024x1024.onnx")
	detClasses := filepath.Join(configDir, "ndl.yaml")
	recWeights30 := filepath.Join(modelDir, "parseq-ndl-24x256-30-tiny-189epoch-tegaki3-r8data-202604.onnx")
	recWeights50 := filepath.Join(modelDir, "parseq-ndl-24x384-50-tiny-300epoch-tegaki3-r8data-202604.onnx")
	recWeights100 := filepath.Join(modelDir, "parseq-ndl-24x768-100-tiny-153epoch-tegaki3-r8data-202604.onnx")
	recClasses := filepath.Join(configDir, "NDLmoji.yaml")

	detector, err := NewDEIM(runtime, env, detWeights, detClasses, 0.2, 0.25, 0.2, device)
	if err != nil {
		env.Close()
		runtime.Close()
		return nil, fmt.Errorf("failed to initialize DEIM: %w", err)
	}

	charList, err := loadCharList(recClasses)
	if err != nil {
		detector.Close()
		env.Close()
		runtime.Close()
		return nil, fmt.Errorf("failed to load character list: %w", err)
	}

	rec100, err := NewPARSEQ(runtime, env, recWeights100, charList, device)
	if err != nil {
		detector.Close()
		env.Close()
		runtime.Close()
		return nil, fmt.Errorf("failed to initialize PARSeq (100): %w", err)
	}

	rec30, err := NewPARSEQ(runtime, env, recWeights30, charList, device)
	if err != nil {
		detector.Close()
		rec100.Close()
		env.Close()
		runtime.Close()
		return nil, fmt.Errorf("failed to initialize PARSeq (30): %w", err)
	}

	rec50, err := NewPARSEQ(runtime, env, recWeights50, charList, device)
	if err != nil {
		detector.Close()
		rec100.Close()
		rec30.Close()
		env.Close()
		runtime.Close()
		return nil, fmt.Errorf("failed to initialize PARSeq (50): %w", err)
	}

	return &Engine{
		runtime:  runtime,
		env:      env,
		detector: detector,
		rec30:    rec30,
		rec50:    rec50,
		rec100:   rec100,
	}, nil
}

// Close releases all model resources.
func (e *Engine) Close() {
	if e.detector != nil {
		e.detector.Close()
	}
	if e.rec30 != nil {
		e.rec30.Close()
	}
	if e.rec50 != nil {
		e.rec50.Close()
	}
	if e.rec100 != nil {
		e.rec100.Close()
	}
	if e.env != nil {
		e.env.Close()
	}
	if e.runtime != nil {
		e.runtime.Close()
	}
}

// Recognize performs OCR on a single image and returns detected text blocks.
func (e *Engine) Recognize(ctx context.Context, img image.Image) ([]TextBlock, error) {
	imgData, imgH, imgW := ImageToRGB(img)

	detections, err := e.detector.Detect(ctx, imgData, imgH, imgW)
	if err != nil {
		return nil, fmt.Errorf("detection failed: %w", err)
	}

	// Collect line regions directly from detection boxes
	type lineRegion struct {
		xmin, ymin, xmax, ymax int
	}
	var lineObjs []*recogLine
	var lineRegions []lineRegion
	for i, det := range detections {
		if !strings.HasPrefix(det.ClassName, "line_") {
			continue
		}
		xmin := max(int(det.Box[0]), 0)
		ymin := max(int(det.Box[1]), 0)
		xmax := min(int(det.Box[2]), imgW)
		ymax := min(int(det.Box[3]), imgH)
		lineW := xmax - xmin
		lineH := ymax - ymin
		if lineW <= 0 || lineH <= 0 {
			continue
		}
		lineImg := CropRegion(imgData, imgW, xmin, ymin, lineW, lineH)
		lineObjs = append(lineObjs, &recogLine{
			ImgData:     lineImg,
			ImgH:        lineH,
			ImgW:        lineW,
			Idx:         i,
			PredCharCnt: det.PredCharCount,
			Det:         det,
		})
		lineRegions = append(lineRegions, lineRegion{xmin, ymin, xmax, ymax})
	}

	if len(lineObjs) == 0 {
		return nil, nil
	}

	if err := processCascade(ctx, lineObjs, e.rec30, e.rec50, e.rec100); err != nil {
		return nil, err
	}

	var blocks []TextBlock
	for i, line := range lineObjs {
		r := lineRegions[i]
		blocks = append(blocks, TextBlock{
			Text: line.PredStr,
			BoundingBox: [4][2]int{
				{r.xmin, r.ymin}, // topLeft
				{r.xmax, r.ymin}, // topRight
				{r.xmax, r.ymax}, // bottomRight
				{r.xmin, r.ymax}, // bottomLeft
			},
			Category:   line.Det.ClassName,
			Confidence: line.Det.Confidence,
		})
	}

	return blocks, nil
}

// recogLine holds a cropped line image and metadata for recognition.
type recogLine struct {
	ImgData     []float32
	ImgH, ImgW  int
	Idx         int
	PredCharCnt float32
	PredStr     string
	Det         Detection
}

// processCascade performs cascade recognition using 3 models of different sizes.
func processCascade(ctx context.Context, lines []*recogLine, rec30, rec50, rec100 *PARSEQ) error {
	var target30, target50, target100 []*recogLine
	for _, line := range lines {
		switch line.PredCharCnt {
		case 3:
			target30 = append(target30, line)
		case 2:
			target50 = append(target50, line)
		default:
			target100 = append(target100, line)
		}
	}

	for _, line := range target30 {
		if err := ctx.Err(); err != nil {
			return err
		}
		predStr, err := rec30.Read(ctx, line.ImgData, line.ImgH, line.ImgW)
		if err != nil {
			return fmt.Errorf("recognition failed (rec30): %w", err)
		}
		if utf8.RuneCountInString(predStr) >= 25 {
			target50 = append(target50, line)
		} else {
			line.PredStr = predStr
		}
	}

	for _, line := range target50 {
		if err := ctx.Err(); err != nil {
			return err
		}
		predStr, err := rec50.Read(ctx, line.ImgData, line.ImgH, line.ImgW)
		if err != nil {
			return fmt.Errorf("recognition failed (rec50): %w", err)
		}
		if utf8.RuneCountInString(predStr) >= 45 {
			target100 = append(target100, line)
		} else {
			line.PredStr = predStr
		}
	}

	for _, line := range target100 {
		if err := ctx.Err(); err != nil {
			return err
		}
		predStr, err := rec100.Read(ctx, line.ImgData, line.ImgH, line.ImgW)
		if err != nil {
			return fmt.Errorf("recognition failed (rec100): %w", err)
		}
		line.PredStr = predStr
	}

	sort.Slice(lines, func(i, j int) bool {
		return lines[i].Idx < lines[j].Idx
	})
	return nil
}

func loadCharList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read char classes file: %w", err)
	}

	var charObj struct {
		Model struct {
			CharsetTrain string `yaml:"charset_train"`
		} `yaml:"model"`
	}
	if err := yaml.Unmarshal(data, &charObj); err != nil {
		return nil, fmt.Errorf("failed to parse char classes yaml: %w", err)
	}

	var charList []string
	for _, r := range charObj.Model.CharsetTrain {
		charList = append(charList, string(r))
	}
	return charList, nil
}
