package vens

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// ScanError indicates a scanner-level error (no paper, hardware failure, etc.).
type ScanError struct {
	Msg string
}

func (e *ScanError) Error() string { return e.Msg }

// Page holds a single scanned page image.
type Page struct {
	Sheet int    // Physical sheet index (0-based)
	Side  int    // 0=front, 1=back
	JPEG  []byte // Raw JPEG data
}

// DataChannel manages TCP data channel connections (port 53218).
type DataChannel struct {
	host  string
	port  uint16
	token [8]byte
}

// NewDataChannel creates a DataChannel for the given scanner address.
func NewDataChannel(host string, port uint16, token [8]byte) *DataChannel {
	return &DataChannel{host: host, port: port, token: token}
}

// connect opens a TCP connection and reads the welcome packet.
func (d *DataChannel) connect() (net.Conn, error) {
	addr := net.JoinHostPort(d.host, fmt.Sprintf("%d", d.port))
	slog.Debug("data channel connecting", "addr", addr)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("data connect: %w", err)
	}

	welcome := make([]byte, WelcomeSize)
	if _, err := io.ReadFull(conn, welcome); err != nil {
		conn.Close()
		return nil, fmt.Errorf("data welcome: %w", err)
	}
	if err := ValidateWelcome(welcome); err != nil {
		conn.Close()
		return nil, err
	}
	slog.Debug("data channel connected", "addr", addr, "welcome_hex", hex.EncodeToString(welcome))
	return conn, nil
}

// request opens a connection, sends data, reads a length-prefixed response, and closes.
func (d *DataChannel) request(data []byte) ([]byte, error) {
	conn, err := d.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	slog.Debug("data send", "bytes", len(data))
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("data send: %w", err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		return nil, err
	}
	slog.Debug("data recv", "bytes", len(resp))
	return resp, nil
}

// readResponse reads a length-prefixed VENS response from a connection.
func readResponse(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen < 4 {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}
	resp := make([]byte, respLen)
	copy(resp[:4], lenBuf)
	if _, err := io.ReadFull(r, resp[4:]); err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return resp, nil
}

// GetDeviceInfo queries device identity (cmd=0x06, sub=0x12).
func (d *DataChannel) GetDeviceInfo() (*DataDeviceInfo, error) {
	slog.Debug("getting device info...")
	resp, err := d.request(MarshalGetDeviceInfo(d.token))
	if err != nil {
		return nil, err
	}
	info, err := ParseDataDeviceInfo(resp)
	if err != nil {
		return nil, err
	}
	slog.Debug("device info OK", "deviceName", info.DeviceName, "firmware", fmt.Sprintf("%d.%d", info.FirmwareMajor, info.FirmwareMinor))
	return info, nil
}

// GetScanParams queries scanner capabilities (cmd=0x06, sub=0x90).
func (d *DataChannel) GetScanParams() ([]byte, error) {
	slog.Debug("getting scan params...")
	resp, err := d.request(MarshalGetScanParams(d.token))
	if err != nil {
		return nil, err
	}
	slog.Debug("scan params OK", "bytes", len(resp))
	return resp, nil
}

// GetScanSettings queries current scan settings (cmd=0x06, sub=0xD8).
func (d *DataChannel) GetScanSettings() ([]byte, error) {
	slog.Debug("getting scan settings...")
	resp, err := d.request(MarshalGetScanSettings(d.token))
	if err != nil {
		return nil, err
	}
	slog.Debug("scan settings OK", "bytes", len(resp))
	return resp, nil
}

// SetConfig sends scanner config (cmd=0x08).
func (d *DataChannel) SetConfig() ([]byte, error) {
	slog.Debug("setting config...")
	resp, err := d.request(MarshalConfigCommand(d.token))
	if err != nil {
		return nil, err
	}
	slog.Debug("config OK", "bytes", len(resp))
	return resp, nil
}

// RunScan executes a full scan session and returns all scanned pages.
// The scan uses a single long-lived TCP connection.
func (d *DataChannel) RunScan(cfg ScanConfig, onPage func(Page)) ([]Page, error) {
	slog.Debug("starting scan session", "colorMode", cfg.ColorMode, "quality", cfg.Quality, "duplex", cfg.Duplex, "paperSize", cfg.PaperSize)
	conn, err := d.connect()
	if err != nil {
		return nil, err
	}
	defer func() {
		// End scan session (sub=0xD6) — required to reset scanner state
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(MarshalEndScan(d.token)); err != nil {
			slog.Debug("end scan send failed", "err", err)
		} else if _, err := readResponse(conn); err != nil {
			slog.Debug("end scan response failed", "err", err)
		} else {
			slog.Debug("end scan session OK")
		}
		conn.Close()
	}()

	// No overall deadline for scanning — individual reads have their own timeouts
	sendAndRecv := func(data []byte) ([]byte, error) {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		slog.Debug("scan send", "bytes", len(data))
		if _, err := conn.Write(data); err != nil {
			return nil, err
		}
		return readResponse(conn)
	}

	// Step 1: Get current settings
	slog.Debug("scan step 1: getting current scan settings...")
	resp, err := sendAndRecv(MarshalGetScanSettings(d.token))
	if err != nil {
		return nil, fmt.Errorf("get settings: %w", err)
	}
	slog.Debug("get settings response", "bytes", len(resp))

	// Step 2: Write scan config
	slog.Debug("scan step 2: writing scan config...")
	resp, err = sendAndRecv(MarshalScanConfig(d.token, cfg))
	if err != nil {
		return nil, fmt.Errorf("set scan config: %w", err)
	}
	slog.Debug("set config response", "bytes", len(resp), "hex", hex.EncodeToString(resp))

	// Step 2.5: Write tone curve for bleed-through reduction (sub=0xDB)
	if cfg.BleedThrough {
		slog.Debug("scan step 2.5: writing bleed-through tone curve...")
		resp, err = sendAndRecv(MarshalWriteToneCurve(d.token))
		if err != nil {
			return nil, fmt.Errorf("write tone curve: %w", err)
		}
		slog.Debug("tone curve response", "bytes", len(resp))
	}

	// Step 3: Prepare scan
	slog.Debug("scan step 3: preparing scan...")
	resp, err = sendAndRecv(MarshalPrepareScan(d.token))
	if err != nil {
		return nil, fmt.Errorf("prepare scan: %w", err)
	}
	slog.Debug("prepare scan response", "bytes", len(resp))

	// Step 4: Get status — check for paper in ADF
	slog.Debug("scan step 4: getting status...")
	resp, err = sendAndRecv(MarshalGetStatus(d.token))
	if err != nil {
		return nil, fmt.Errorf("get status: %w", err)
	}
	slog.Debug("status response", "bytes", len(resp), "hex", hex.EncodeToString(resp))
	if len(resp) >= 44 {
		scanStatus := binary.BigEndian.Uint32(resp[40:44])
		slog.Info("scan status", "status", fmt.Sprintf("0x%08X", scanStatus))
		if scanStatus&0x80 != 0 {
			return nil, &ScanError{Msg: "no paper in ADF"}
		}
	}

	// Step 5: Wait for scan to start
	slog.Debug("scan step 5: waiting for scan to start...")
	conn.SetDeadline(time.Now().Add(120 * time.Second)) // Long timeout for user interaction
	if _, err := conn.Write(MarshalWaitForScan(d.token)); err != nil {
		return nil, fmt.Errorf("wait for scan: %w", err)
	}
	resp, err = readResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("wait for scan response: %w", err)
	}
	if len(resp) >= 16 {
		waitStatus := binary.BigEndian.Uint32(resp[12:16])
		slog.Info("scan started", "waitStatus", waitStatus)
		if waitStatus != 0 {
			return nil, &ScanError{Msg: fmt.Sprintf("WaitForScan returned status=%d (expected 0)", waitStatus)}
		}
	} else {
		slog.Info("scan started!")
	}

	// Step 6: Receive pages
	var pages []Page
	physicalSheet := 0
	transferSheet := 0
	sidesPerSheet := 1
	if cfg.Duplex {
		sidesPerSheet = 2
	}

	for {
		for sideIdx := range sidesPerSheet {
			sideName := "front"
			if sideIdx == 1 {
				sideName = "back"
			}
			slog.Debug("transferring page", "sheet", physicalSheet, "side", sideName, "transferSheet", transferSheet)
			jpeg, err := d.transferPageChunks(conn, transferSheet, sideIdx == 1)
			if err != nil {
				return pages, fmt.Errorf("page transfer: %w", err)
			}

			page := Page{Sheet: physicalSheet, Side: sideIdx, JPEG: jpeg}
			pages = append(pages, page)
			slog.Info("page received", "sheet", physicalSheet, "side", sideName, "bytes", len(jpeg))
			if onPage != nil {
				onPage(page)
			}

			// Page metadata after each transfer
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(MarshalGetPageMetadata(d.token)); err != nil {
				return pages, fmt.Errorf("page metadata send: %w", err)
			}
			metaResp, err := readResponse(conn)
			if err != nil {
				return pages, fmt.Errorf("page metadata recv: %w", err)
			}
			slog.Debug("page metadata", "bytes", len(metaResp))

			transferSheet++
		}

		// Check status
		slog.Debug("checking status...")
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(MarshalGetStatus(d.token)); err != nil {
			return pages, fmt.Errorf("status check: %w", err)
		}
		statusResp, err := readResponse(conn)
		if err != nil {
			return pages, fmt.Errorf("status check recv: %w", err)
		}
		if len(statusResp) >= 44 {
			scanStatus := binary.BigEndian.Uint32(statusResp[40:44])
			slog.Info("scan status", "status", fmt.Sprintf("0x%08X", scanStatus))
		}

		// Wait for next sheet
		slog.Debug("waiting for next sheet...")
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(MarshalWaitForScan(d.token)); err != nil {
			return pages, fmt.Errorf("wait next sheet: %w", err)
		}
		resp, err := readResponse(conn)
		if err != nil {
			return pages, fmt.Errorf("wait next sheet recv: %w", err)
		}
		if len(resp) >= 16 {
			waitStatus := binary.BigEndian.Uint32(resp[12:16])
			if waitStatus != 0 {
				slog.Info("scan complete", "waitStatus", waitStatus)
				break
			}
		}

		physicalSheet++
	}

	nonEmpty := 0
	for _, p := range pages {
		if len(p.JPEG) > 0 {
			nonEmpty++
		}
	}
	slog.Info("scan finished", "total_pages", len(pages), "non_empty", nonEmpty)
	return pages, nil
}

// transferPageChunks reads all JPEG chunks for a single page side.
// The scanner sends data in 256KB chunks; page_type=2 marks the final chunk.
func (d *DataChannel) transferPageChunks(conn net.Conn, sheet int, backSide bool) ([]byte, error) {
	pageBase := sheet << 8
	var jpegBuf []byte

	for chunk := 0; ; chunk++ {
		pageNum := pageBase | chunk
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		if _, err := conn.Write(MarshalPageTransfer(d.token, pageNum, backSide)); err != nil {
			return nil, fmt.Errorf("chunk %d send: %w", chunk, err)
		}

		// Read length prefix first to detect error responses (< 42 bytes)
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, fmt.Errorf("chunk %d length: %w", chunk, err)
		}
		totalLen := binary.BigEndian.Uint32(lenBuf)
		if totalLen < uint32(PageHeaderSize) {
			// Scanner returned an error/short response, not a page header
			if totalLen > 4 {
				discard := make([]byte, totalLen-4)
				io.ReadFull(conn, discard)
			}
			return nil, &ScanError{Msg: fmt.Sprintf("page transfer error: expected page header, got %d bytes", totalLen)}
		}

		restBuf := make([]byte, PageHeaderSize-4)
		if _, err := io.ReadFull(conn, restBuf); err != nil {
			return nil, fmt.Errorf("chunk %d header: %w", chunk, err)
		}
		headerBuf := make([]byte, PageHeaderSize)
		copy(headerBuf[:4], lenBuf)
		copy(headerBuf[4:], restBuf)
		header, err := ParsePageHeader(headerBuf)
		if err != nil {
			return nil, fmt.Errorf("chunk %d parse: %w", chunk, err)
		}

		jpegSize := header.JPEGSize()
		if jpegSize > 0 {
			jpegChunk := make([]byte, jpegSize)
			if _, err := io.ReadFull(conn, jpegChunk); err != nil {
				return nil, fmt.Errorf("chunk %d data: %w", chunk, err)
			}
			jpegBuf = append(jpegBuf, jpegChunk...)
		}

		slog.Debug("chunk", "pageNum", fmt.Sprintf("0x%04X", pageNum), "pageType", header.PageType, "chunk_bytes", jpegSize, "total_bytes", len(jpegBuf))

		if header.PageType == PageTypeFinal {
			break
		}
	}

	slog.Debug("transfer complete", "sheet", sheet, "bytes", len(jpegBuf), "chunks", len(jpegBuf)/262144+1)
	return jpegBuf, nil
}

// CheckADFStatus queries the scanner ADF status and returns whether paper is present.
func (d *DataChannel) CheckADFStatus() (bool, error) {
	slog.Debug("checking ADF status...")
	resp, err := d.request(MarshalGetStatus(d.token))
	if err != nil {
		return false, err
	}
	if len(resp) < 44 {
		return false, errors.New("status response too short for ADF check")
	}
	scanStatus := binary.BigEndian.Uint32(resp[40:44])
	hasPaper := scanStatus&0x80 == 0
	slog.Debug("ADF status check", "scanStatus", fmt.Sprintf("0x%08X", scanStatus), "paper", hasPaper)
	return hasPaper, nil
}
