package ndlocr

import (
	"context"
	"fmt"
	"os"

	ort "github.com/shota3506/onnxruntime-purego/onnxruntime"
	xdraw "golang.org/x/image/draw"
	"gopkg.in/yaml.v3"
)

// Detection represents a single detected object.
type Detection struct {
	ClassIndex    int
	Confidence    float32
	Box           [4]int32 // xmin, ymin, xmax, ymax
	PredCharCount float32
	ClassName     string
}

// DEIM is the layout detection model using ONNX Runtime.
type DEIM struct {
	runtime        *ort.Runtime
	session        *ort.Session
	classes        map[int]string
	inputH, inputW int64
	scoreThreshold float32
	confThreshold  float32
	iouThreshold   float32
}

type classesYAML struct {
	Names map[int]string `yaml:"names"`
}

// NewDEIM creates a new DEIM detector.
func NewDEIM(runtime *ort.Runtime, env *ort.Env, modelPath, classesPath string, scoreThreshold, confThreshold, iouThreshold float64, device string) (*DEIM, error) {
	data, err := os.ReadFile(classesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read classes file: %w", err)
	}
	var cy classesYAML
	if err := yaml.Unmarshal(data, &cy); err != nil {
		return nil, fmt.Errorf("failed to parse classes yaml: %w", err)
	}

	d := &DEIM{
		runtime:        runtime,
		classes:        cy.Names,
		scoreThreshold: float32(scoreThreshold),
		confThreshold:  float32(confThreshold),
		iouThreshold:   float32(iouThreshold),
	}

	opts := &ort.SessionOptions{}
	if device == "cuda" {
		opts.ExecutionProviders = []string{"CUDAExecutionProvider"}
	}

	session, err := runtime.NewSession(env, modelPath, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create ONNX session: %w", err)
	}
	d.session = session

	// Model input shape is fixed at 800x800 (despite filename suggesting 1024x1024)
	d.inputH, d.inputW = 800, 800

	return d, nil
}

// Detect performs layout detection on an image.
// Matches Python: pad to square -> resize to input size -> pass input size as orig_target_sizes.
func (d *DEIM) Detect(ctx context.Context, imgData []float32, imgH, imgW int) ([]Detection, error) {
	// Pad to square (matching Python preprocess)
	padded, paddedSize := PadToSquare(imgData, imgH, imgW)

	// Use BiLinear to match upstream ndlocr-lite v1.2.0 (PIL.Image.resize default).
	resized := ResizeHWC(padded, paddedSize, paddedSize, int(d.inputH), int(d.inputW), xdraw.BiLinear)
	nchw := PreprocessDEIM(resized, int(d.inputH), int(d.inputW))

	// Create input tensors
	inputTensor, err := ort.NewTensorValue(d.runtime, nchw, []int64{1, 3, d.inputH, d.inputW})
	if err != nil {
		return nil, fmt.Errorf("failed to create input tensor: %w", err)
	}
	defer inputTensor.Close()

	// Pass model input dimensions as orig_target_sizes (matching Python)
	origSizeData := []int64{d.inputH, d.inputW}
	origSizeTensor, err := ort.NewTensorValue(d.runtime, origSizeData, []int64{1, 2})
	if err != nil {
		return nil, fmt.Errorf("failed to create orig size tensor: %w", err)
	}
	defer origSizeTensor.Close()

	inputNames := d.session.InputNames()
	outputs, err := d.session.Run(ctx, map[string]*ort.Value{
		inputNames[0]: inputTensor,
		inputNames[1]: origSizeTensor,
	})
	if err != nil {
		return nil, fmt.Errorf("DEIM inference failed: %w", err)
	}

	outputNames := d.session.OutputNames()

	// Extract output data
	classIDs, _, err := ort.GetTensorData[int64](outputs[outputNames[0]])
	if err != nil {
		return nil, fmt.Errorf("failed to get class IDs: %w", err)
	}

	bboxes, _, err := ort.GetTensorData[float32](outputs[outputNames[1]])
	if err != nil {
		return nil, fmt.Errorf("failed to get bboxes: %w", err)
	}

	scores, _, err := ort.GetTensorData[float32](outputs[outputNames[2]])
	if err != nil {
		return nil, fmt.Errorf("failed to get scores: %w", err)
	}

	var charCounts []float32
	if len(outputNames) > 3 {
		charCountsRaw, _, err := ort.GetTensorData[int64](outputs[outputNames[3]])
		if err == nil {
			charCounts = make([]float32, len(charCountsRaw))
			for i, v := range charCountsRaw {
				charCounts[i] = float32(v)
			}
		}
	}
	if charCounts == nil {
		charCounts = make([]float32, len(scores))
		for i := range charCounts {
			charCounts[i] = 100.0
		}
	}

	// Close output values
	for _, v := range outputs {
		v.Close()
	}

	return d.postprocess(classIDs, bboxes, scores, charCounts, paddedSize), nil
}

func (d *DEIM) postprocess(classIDs []int64, bboxes []float32, scores []float32, charCounts []float32, paddedSize int) []Detection {
	// Scale from model input coordinates to padded image coordinates.
	// Matches Python: scales = [paddedSize/inputW, paddedSize/inputW, ...]
	scale := float32(paddedSize) / float32(d.inputW)

	var detections []Detection
	numDet := len(scores)
	for i := 0; i < numDet; i++ {
		if scores[i] <= d.confThreshold {
			continue
		}
		classIndex := int(classIDs[i]) - 1
		if classIndex < 0 || classIndex >= len(d.classes) {
			continue
		}

		x1 := int32(bboxes[i*4+0] * scale)
		y1 := int32(bboxes[i*4+1] * scale)
		x2 := int32(bboxes[i*4+2] * scale)
		y2 := int32(bboxes[i*4+3] * scale)

		// Clip to padded image bounds (matches upstream ndlocr-lite a081a6f).
		ps := int32(paddedSize)
		x1 = clipInt32(x1, 0, ps)
		x2 = clipInt32(x2, 0, ps)
		y1 = clipInt32(y1, 0, ps)
		y2 = clipInt32(y2, 0, ps)

		detections = append(detections, Detection{
			ClassIndex:    classIndex,
			Confidence:    scores[i],
			Box:           [4]int32{x1, y1, x2, y2},
			PredCharCount: charCounts[i],
			ClassName:     d.classes[classIndex],
		})
	}

	return detections
}

// Classes returns the class mapping.
func (d *DEIM) Classes() map[int]string {
	return d.classes
}

// clipInt32 clamps v to [lo, hi].
func clipInt32(v, lo, hi int32) int32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Close frees resources.
func (d *DEIM) Close() {
	if d.session != nil {
		d.session.Close()
	}
}
