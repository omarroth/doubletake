package airplay

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func TestRawH264AccessUnitsPreservePrefixSEIAndDrainEOF(t *testing.T) {
	sps, pps := []byte{0x67, 0x42, 0, 0x1f}, []byte{0x68, 0xce, 6}
	sei1, sei2 := []byte{6, 5, 1, 0x11, 0x80}, []byte{6, 5, 1, 0x22, 0x80}
	first := [][]byte{sps, pps, sei1, {0x65, 0x80, 1}, {0x65, 0x40, 2}}
	second := [][]byte{sei2, {0x61, 0x80, 3}}
	for _, format := range []string{"annexb", "avcc"} {
		t.Run(format, func(t *testing.T) {
			var encoded []byte
			for _, nal := range append(append([][]byte(nil), first...), second...) {
				if format == "avcc" {
					encoded = append(encoded, receiverTestAVCC(nal)...)
				} else {
					encoded = append(encoded, joinAnnexBNALs(nal)...)
				}
			}
			// Force start codes, length fields and NAL payloads across reads. The
			// last read returns data and EOF together, as permitted by io.Reader.
			reader := newRawH264AccessUnitReader(iotest.DataErrReader(iotest.OneByteReader(bytes.NewReader(encoded))))
			for i, nals := range [][][]byte{first, second} {
				unit, err := reader.ReadVideoAccessUnit()
				if err != nil {
					t.Fatalf("unit %d: %v", i, err)
				}
				if want := joinAnnexBNALs(nals...); !bytes.Equal(unit.AnnexB, want) {
					t.Fatalf("unit %d = %x, want %x", i, unit.AnnexB, want)
				}
				if !unit.PTS.IsZero() {
					t.Fatal("raw compatibility capture invented a source timestamp")
				}
			}
			if unit, err := reader.ReadVideoAccessUnit(); !errors.Is(err, io.EOF) || len(unit.AnnexB) != 0 {
				t.Fatalf("read after final picture = (%x, %v), want EOF", unit.AnnexB, err)
			}
		})
	}
}

func TestRawH264AccessUnitsRejectTruncatedAVCC(t *testing.T) {
	reader := newRawH264AccessUnitReader(bytes.NewReader([]byte{0, 0, 0, 6, 0x65, 0x80}))
	if _, err := reader.ReadVideoAccessUnit(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want truncated NAL", err)
	}
}
