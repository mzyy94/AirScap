package ndlocr

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	ort "github.com/shota3506/onnxruntime-purego/onnxruntime"
)

// PARSEQ is the character recognition model using ONNX Runtime.
type PARSEQ struct {
	runtime  *ort.Runtime
	session  *ort.Session
	charList []string
	inputH   int64
	inputW   int64
}

// NewPARSEQ creates a new PARSeq recognizer.
// Input dimensions are parsed from the model filename (e.g. parseq-ndl-24x256-30-...).
func NewPARSEQ(runtime *ort.Runtime, env *ort.Env, modelPath string, charList []string, device string) (*PARSEQ, error) {
	opts := &ort.SessionOptions{
		IntraOpNumThreads: 1,
	}
	if device == "cuda" {
		opts.ExecutionProviders = []string{"CUDAExecutionProvider"}
	}

	session, err := runtime.NewSession(env, modelPath, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create ONNX session: %w", err)
	}

	inputH, inputW, err := parsePARSeqDims(modelPath)
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to parse model dimensions from %s: %w", filepath.Base(modelPath), err)
	}

	return &PARSEQ{
		runtime:  runtime,
		session:  session,
		charList: charList,
		inputH:   int64(inputH),
		inputW:   int64(inputW),
	}, nil
}

// parsePARSeqDims extracts H and W from a filename like "parseq-ndl-24x256-30-...".
func parsePARSeqDims(modelPath string) (int, int, error) {
	base := filepath.Base(modelPath)
	parts := strings.Split(base, "-")
	for _, p := range parts {
		if strings.Contains(p, "x") {
			dims := strings.SplitN(p, "x", 2)
			if len(dims) == 2 {
				h, err1 := strconv.Atoi(dims[0])
				w, err2 := strconv.Atoi(dims[1])
				if err1 == nil && err2 == nil {
					return h, w, nil
				}
			}
		}
	}
	return 0, 0, fmt.Errorf("cannot parse dimensions from filename %s", base)
}

// Read recognizes text from a cropped line image.
// Vertical text (h > w) is rotated 90° CCW before recognition, matching Python's behavior.
func (p *PARSEQ) Read(ctx context.Context, imgData []float32, imgH, imgW int) (string, error) {
	h, w := imgH, imgW
	data := imgData
	if h > w {
		data, h, w = Rotate90CCW(data, h, w)
	}

	nchw := PreprocessPARSeq(data, h, w, int(p.inputH), int(p.inputW))

	inputTensor, err := ort.NewTensorValue(p.runtime, nchw, []int64{1, 3, p.inputH, p.inputW})
	if err != nil {
		return "", fmt.Errorf("failed to create input tensor: %w", err)
	}
	defer inputTensor.Close()

	inputNames := p.session.InputNames()
	outputs, err := p.session.Run(ctx, map[string]*ort.Value{
		inputNames[0]: inputTensor,
	})
	if err != nil {
		return "", fmt.Errorf("PARSeq inference failed: %w", err)
	}

	outputNames := p.session.OutputNames()
	logits, shape, err := ort.GetTensorData[float32](outputs[outputNames[0]])
	if err != nil {
		for _, v := range outputs {
			v.Close()
		}
		return "", fmt.Errorf("failed to get output data: %w", err)
	}

	// Close output values
	for _, v := range outputs {
		v.Close()
	}

	// Decode: argmax over vocabulary dimension
	// Shape: [1, seqLen, vocabSize]
	seqLen := int(shape[1])
	vocabSize := int(shape[2])

	var result []string
	for t := 0; t < seqLen; t++ {
		maxIdx := 0
		maxVal := logits[t*vocabSize]
		for v := 1; v < vocabSize; v++ {
			val := logits[t*vocabSize+v]
			if val > maxVal {
				maxVal = val
				maxIdx = v
			}
		}
		if maxIdx == 0 { // EOS/blank token
			break
		}
		if maxIdx-1 < len(p.charList) {
			result = append(result, p.charList[maxIdx-1])
		}
	}

	return strings.Join(result, ""), nil
}

// Close frees resources.
func (p *PARSEQ) Close() {
	if p.session != nil {
		p.session.Close()
	}
}
