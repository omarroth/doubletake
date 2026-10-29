package airplay

import (
	"fmt"
	"io"
)

// rawH264AccessUnitReader adapts the older, untimestamped capture output to the
// same complete-picture interface as RTP capture. Only this compatibility path
// needs to discover frame boundaries from the elementary stream.
type rawH264AccessUnitReader struct {
	reader  io.Reader
	parser  *h264Parser
	buf     []byte
	nals    [][]byte
	readErr error
	unit    []byte
	hasVCL  bool
}

func newRawH264AccessUnitReader(reader io.Reader) *rawH264AccessUnitReader {
	return &rawH264AccessUnitReader{reader: reader, parser: newH264Parser(), buf: make([]byte, 64*1024)}
}

func (r *rawH264AccessUnitReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	for {
		for len(r.nals) == 0 && r.readErr == nil {
			n, err := r.reader.Read(r.buf)
			r.nals = r.parser.Push(r.buf[:n])
			r.readErr = err
			if err == io.EOF {
				last, flushErr := r.parser.finish()
				if flushErr != nil {
					r.readErr = flushErr
				} else if len(last) != 0 {
					r.nals = append(r.nals, last)
				}
			}
		}
		if len(r.nals) == 0 {
			if r.readErr == io.EOF && r.hasVCL {
				return r.takeUnit(), nil
			}
			return VideoAccessUnit{}, r.readErr
		}
		raw := stripStartCode(r.nals[0])
		if len(raw) == 0 {
			r.nals = r.nals[1:]
			continue
		}
		typ := raw[0] & 0x1f
		// H.264 7.4.1.2.3: SEI and parameter sets following a picture begin
		// the next access unit. In particular, do not attach prefix SEI to the
		// previous picture just because the encoder omitted AUDs.
		prefix := typ == 6 || typ == 7 || typ == 8 || typ == 9 || typ >= 14 && typ <= 18
		firstSlice := (typ == 1 || typ == 2 || typ == 5) && isFirstSlice(raw)
		if r.hasVCL && (prefix || firstSlice) {
			return r.takeUnit(), nil // Leave this NAL for the next picture.
		}
		r.nals = r.nals[1:]
		if len(r.unit)+4+len(raw) > maxVideoAccessUnitBytes {
			return VideoAccessUnit{}, fmt.Errorf("raw H.264 access unit exceeds %d bytes", maxVideoAccessUnitBytes)
		}
		r.unit = append(r.unit, annexBLongStartCode[:]...)
		r.unit = append(r.unit, raw...)
		r.hasVCL = r.hasVCL || typ >= 1 && typ <= 5
	}
}

func (r *rawH264AccessUnitReader) takeUnit() VideoAccessUnit {
	unit := VideoAccessUnit{AnnexB: r.unit}
	r.unit, r.hasVCL = nil, false
	return unit
}

// finish drains the final Annex-B NAL, which has no following start code at EOF.
// Length-prefixed NALs are already emitted by Push; any remaining bytes in that
// format indicate a truncated NAL rather than a complete final picture.
func (p *h264Parser) finish() ([]byte, error) {
	if len(p.buf) == 0 {
		return nil, nil
	}
	if findStartCode(p.buf, 0) != 0 {
		return nil, fmt.Errorf("truncated H.264 NAL: %w", io.ErrUnexpectedEOF)
	}
	last := p.buf
	p.buf = nil
	return last, nil
}
