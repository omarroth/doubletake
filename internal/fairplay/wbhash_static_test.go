package fairplay

import (
	"encoding/binary"
	"testing"
)

func TestWBHashStaticPointerTableMatchesSnapshot(t *testing.T) {
	page := snapshotPageForTest(t, wbStaticPointerTableBase)
	for i, got := range wbStaticPointerTable {
		want := binary.LittleEndian.Uint64(page[i*8:])
		if got != want {
			t.Fatalf("wbStaticPointerTable[%d] = 0x%x, want snapshot value 0x%x", i, got, want)
		}
	}
}

func TestWBHashStaticVectorConstantsMatchSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticVectorConstPageBase] {
		t.Skip("vector constant page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticVectorConstPageBase)
	for i, got := range wbStaticVectorConstants {
		offset := 0x5a0 + i*0x10
		want := [2]uint64{
			binary.LittleEndian.Uint64(page[offset:]),
			binary.LittleEndian.Uint64(page[offset+8:]),
		}
		if got != want {
			t.Fatalf("wbStaticVectorConstants[%d] = 0x%x, want snapshot value 0x%x", i, got, want)
		}
	}
}

func TestWBHashStaticBranchOffsetsMatchSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticBranchPageBase] {
		t.Skip("branch offset page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticBranchPageBase)
	for i, got := range wbStaticEncodedWordCOffsets {
		offset := 0x570 + i*4
		want := int32(binary.LittleEndian.Uint32(page[offset:]))
		if got != want {
			t.Fatalf("wbStaticEncodedWordCOffsets[%d] = %d, want snapshot value %d", i, got, want)
		}
	}
	for i, got := range wbStaticPaddingZeroOffsets {
		offset := 0x590 + i*4
		want := int32(binary.LittleEndian.Uint32(page[offset:]))
		if got != want {
			t.Fatalf("wbStaticPaddingZeroOffsets[%d] = %d, want snapshot value %d", i, got, want)
		}
	}
}

func TestWBHashStaticPage130EMatchesSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticPage130EBase] {
		t.Skip("0x1a130e000 page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticPage130EBase)
	for _, offset := range []uint64{0x2b4, 0x500, 0x918, 0x928} {
		got := wbStaticPage130ERead32(wbStaticPage130EBase + offset)
		want := binary.LittleEndian.Uint32(page[offset:])
		if got != want {
			t.Fatalf("wbStaticPage130ERead32(0x%x) = 0x%x, want snapshot value 0x%x", wbStaticPage130EBase+offset, got, want)
		}
	}
	for i, got := range wbStaticPage130EBytes942 {
		want := page[0x942+i]
		if got != want {
			t.Fatalf("wbStaticPage130EBytes942[%d] = 0x%x, want snapshot value 0x%x", i, got, want)
		}
	}
}

func TestWBHashStaticPage130DMatchesSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticPage130DBase] {
		t.Skip("0x1a130d000 page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticPage130DBase)
	got, ok := wbStaticPage130DRead32OK(wbStaticPage130DBase + 0x70c)
	if !ok {
		t.Fatalf("wbStaticPage130DRead32OK did not handle branch table slot")
	}
	want := binary.LittleEndian.Uint32(page[0x70c:])
	if got != want {
		t.Fatalf("wbStaticPage130DRead32OK(0x%x) = 0x%x, want snapshot value 0x%x", wbStaticPage130DBase+0x70c, got, want)
	}
	for i, got := range wbStaticPage130DBytesD20 {
		want := page[0xd20+i]
		if got != want {
			t.Fatalf("wbStaticPage130DBytesD20[%d] = 0x%x, want snapshot value 0x%x", i, got, want)
		}
	}
}

func TestWBHashStaticPage1309MatchesSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticPage1309Base] {
		t.Skip("0x1a1309000 page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticPage1309Base)
	for _, offset := range []uint64{0x230, 0x238, 0x23c, 0x244, 0x248, 0x250, 0x254, 0x258, 0x25c, 0x260, 0x264, 0x268, 0x26c, 0x274, 0x278} {
		got, ok := wbStaticPage1309Read32OK(wbStaticPage1309Base + offset)
		if !ok {
			t.Fatalf("wbStaticPage1309Read32OK did not handle offset 0x%x", offset)
		}
		want := binary.LittleEndian.Uint32(page[offset:])
		if got != want {
			t.Fatalf("wbStaticPage1309Read32OK(0x%x) = 0x%x, want snapshot value 0x%x", wbStaticPage1309Base+offset, got, want)
		}
	}

	byteRanges := []struct {
		offset uint64
		data   []byte
	}{
		{offset: 0x280, data: wbStaticPage1309Bytes280[:]},
		{offset: 0x2ad, data: wbStaticPage1309Bytes2AD[:]},
		{offset: 0x2e0, data: wbStaticPage1309Bytes2E0[:]},
		{offset: 0x314, data: wbStaticPage1309Bytes314[:]},
		{offset: 0x347, data: wbStaticPage1309Bytes347[:]},
		{offset: 0x37a, data: wbStaticPage1309Bytes37A[:]},
	}
	for _, byteRange := range byteRanges {
		for i, got := range byteRange.data {
			want := page[byteRange.offset+uint64(i)]
			if got != want {
				t.Fatalf("wbStaticPage1309 byte at 0x%x = 0x%x, want snapshot value 0x%x", byteRange.offset+uint64(i), got, want)
			}
		}
	}
}

func TestWBHashStaticPage130AMatchesSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticPage130ABase] {
		t.Skip("0x1a130a000 page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticPage130ABase)
	for _, offset := range []uint64{0x890, 0x894, 0x8ac, 0xcd0, 0xe98} {
		got, ok := wbStaticPage130ARead32OK(wbStaticPage130ABase + offset)
		if !ok {
			t.Fatalf("wbStaticPage130ARead32OK did not handle offset 0x%x", offset)
		}
		want := binary.LittleEndian.Uint32(page[offset:])
		if got != want {
			t.Fatalf("wbStaticPage130ARead32OK(0x%x) = 0x%x, want snapshot value 0x%x", wbStaticPage130ABase+offset, got, want)
		}
	}
	got64, ok := wbStaticPage130ARead64OK(wbStaticPage130ABase + 0x890)
	if !ok {
		t.Fatalf("wbStaticPage130ARead64OK did not handle offset 0x890")
	}
	want64 := binary.LittleEndian.Uint64(page[0x890:])
	if got64 != want64 {
		t.Fatalf("wbStaticPage130ARead64OK(0x%x) = 0x%x, want snapshot value 0x%x", wbStaticPage130ABase+0x890, got64, want64)
	}
	for i, got := range wbStaticPage130ABytes144 {
		want := page[0x144+i]
		if got != want {
			t.Fatalf("wbStaticPage130ABytes144[%d] = 0x%x, want snapshot value 0x%x", i, got, want)
		}
	}
	for i, got := range wbStaticPage130ABytes830 {
		want := page[0x830+i]
		if got != want {
			t.Fatalf("wbStaticPage130ABytes830[%d] = 0x%x, want snapshot value 0x%x", i, got, want)
		}
	}
}

func TestWBHashStaticPage130CMatchesSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticPage130CBase] {
		t.Skip("0x1a130c000 page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticPage130CBase)
	for _, span := range wbStaticPage130CSpans {
		offset := span.addr - wbStaticPage130CBase
		for i, got := range span.data {
			want := page[offset+uint64(i)]
			if got != want {
				t.Fatalf("wbStaticPage130C byte at 0x%x = 0x%x, want snapshot value 0x%x", offset+uint64(i), got, want)
			}
			got8, ok := wbStaticPage130CRead8OK(span.addr + uint64(i))
			if !ok {
				t.Fatalf("wbStaticPage130CRead8OK did not handle offset 0x%x", offset+uint64(i))
			}
			if got8 != want {
				t.Fatalf("wbStaticPage130CRead8OK(0x%x) = 0x%x, want snapshot value 0x%x", span.addr+uint64(i), got8, want)
			}
		}
		for i := 0; i+4 <= len(span.data); i += 4 {
			addr := span.addr + uint64(i)
			got, ok := wbStaticPage130CRead32OK(addr)
			if !ok {
				t.Fatalf("wbStaticPage130CRead32OK did not handle offset 0x%x", offset+uint64(i))
			}
			want := binary.LittleEndian.Uint32(page[offset+uint64(i):])
			if got != want {
				t.Fatalf("wbStaticPage130CRead32OK(0x%x) = 0x%x, want snapshot value 0x%x", addr, got, want)
			}
		}
		for i := 0; i+8 <= len(span.data); i += 8 {
			addr := span.addr + uint64(i)
			got, ok := wbStaticPage130CRead64OK(addr)
			if !ok {
				t.Fatalf("wbStaticPage130CRead64OK did not handle offset 0x%x", offset+uint64(i))
			}
			want := binary.LittleEndian.Uint64(page[offset+uint64(i):])
			if got != want {
				t.Fatalf("wbStaticPage130CRead64OK(0x%x) = 0x%x, want snapshot value 0x%x", addr, got, want)
			}
		}
	}
}

func TestWBHashStaticPage1314MatchesSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticPage1314Base] {
		t.Skip("0x1a1314000 page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticPage1314Base)
	for _, span := range wbStaticPage1314Spans {
		offset := span.addr - wbStaticPage1314Base
		for i, got := range span.data {
			want := page[offset+uint64(i)]
			if got != want {
				t.Fatalf("wbStaticPage1314 byte at 0x%x = 0x%x, want snapshot value 0x%x", offset+uint64(i), got, want)
			}
			got8, ok := wbStaticPage1314Read8OK(span.addr + uint64(i))
			if !ok {
				t.Fatalf("wbStaticPage1314Read8OK did not handle offset 0x%x", offset+uint64(i))
			}
			if got8 != want {
				t.Fatalf("wbStaticPage1314Read8OK(0x%x) = 0x%x, want snapshot value 0x%x", span.addr+uint64(i), got8, want)
			}
		}
		for i := 0; i+4 <= len(span.data); i += 4 {
			addr := span.addr + uint64(i)
			got, ok := wbStaticPage1314Read32OK(addr)
			if !ok {
				t.Fatalf("wbStaticPage1314Read32OK did not handle offset 0x%x", offset+uint64(i))
			}
			want := binary.LittleEndian.Uint32(page[offset+uint64(i):])
			if got != want {
				t.Fatalf("wbStaticPage1314Read32OK(0x%x) = 0x%x, want snapshot value 0x%x", addr, got, want)
			}
		}
		for i := 0; i+8 <= len(span.data); i += 8 {
			addr := span.addr + uint64(i)
			got, ok := wbStaticPage1314Read64OK(addr)
			if !ok {
				t.Fatalf("wbStaticPage1314Read64OK did not handle offset 0x%x", offset+uint64(i))
			}
			want := binary.LittleEndian.Uint64(page[offset+uint64(i):])
			if got != want {
				t.Fatalf("wbStaticPage1314Read64OK(0x%x) = 0x%x, want snapshot value 0x%x", addr, got, want)
			}
		}
	}
}

func TestWBHashStaticPage1311MatchesSnapshot(t *testing.T) {
	if !snapshotPageBasesForTest(t)[wbStaticPage1311Base] {
		t.Skip("0x1a1311000 page is omitted after static inlining")
	}

	page := snapshotPageForTest(t, wbStaticPage1311Base)
	for _, span := range wbStaticPage1311Spans {
		offset := span.addr - wbStaticPage1311Base
		for i, got := range span.data {
			want := page[offset+uint64(i)]
			if got != want {
				t.Fatalf("wbStaticPage1311 byte at 0x%x = 0x%x, want snapshot value 0x%x", offset+uint64(i), got, want)
			}
			got8, ok := wbStaticPage1311Read8OK(span.addr + uint64(i))
			if !ok {
				t.Fatalf("wbStaticPage1311Read8OK did not handle offset 0x%x", offset+uint64(i))
			}
			if got8 != want {
				t.Fatalf("wbStaticPage1311Read8OK(0x%x) = 0x%x, want snapshot value 0x%x", span.addr+uint64(i), got8, want)
			}
		}
		for i := 0; i+4 <= len(span.data); i += 4 {
			addr := span.addr + uint64(i)
			got, ok := wbStaticPage1311Read32OK(addr)
			if !ok {
				t.Fatalf("wbStaticPage1311Read32OK did not handle offset 0x%x", offset+uint64(i))
			}
			want := binary.LittleEndian.Uint32(page[offset+uint64(i):])
			if got != want {
				t.Fatalf("wbStaticPage1311Read32OK(0x%x) = 0x%x, want snapshot value 0x%x", addr, got, want)
			}
		}
		for i := 0; i+8 <= len(span.data); i += 8 {
			addr := span.addr + uint64(i)
			got, ok := wbStaticPage1311Read64OK(addr)
			if !ok {
				t.Fatalf("wbStaticPage1311Read64OK did not handle offset 0x%x", offset+uint64(i))
			}
			want := binary.LittleEndian.Uint64(page[offset+uint64(i):])
			if got != want {
				t.Fatalf("wbStaticPage1311Read64OK(0x%x) = 0x%x, want snapshot value 0x%x", addr, got, want)
			}
		}
	}
}

func TestWBHashStaticInlinedPagesAreReadOnly(t *testing.T) {
	tests := []struct {
		name string
		data [128]byte
	}{
		{name: "all-zeros"},
		{name: "all-0xFF", data: filledPayload(0xff)},
		{name: "capturedM2", data: capturedPayload()},
		{name: "0x42-at-0", data: payloadWithByte(0, 0x42)},
		{name: "0x42-at-63", data: payloadWithByte(63, 0x42)},
		{name: "0x42-at-64", data: payloadWithByte(64, 0x42)},
		{name: "0x42-at-127", data: payloadWithByte(127, 0x42)},
	}

	inlinedPages := []struct {
		name string
		base uint64
	}{
		{name: "fixed constants", base: wbStaticConstPageBase},
		{name: "vector constants", base: wbStaticVectorConstPageBase},
		{name: "branch offsets", base: wbStaticBranchPageBase},
		{name: "0x1a1309000 static branch and byte tables", base: wbStaticPage1309Base},
		{name: "0x1a130a000 static tables", base: wbStaticPage130ABase},
		{name: "0x1a130c000 static branch and byte tables", base: wbStaticPage130CBase},
		{name: "0x1a130d000 static copy data", base: wbStaticPage130DBase},
		{name: "0x1a130e000 static slots", base: wbStaticPage130EBase},
		{name: "0x1a1311000 static branch tables", base: wbStaticPage1311Base},
		{name: "0x1a1314000 static branch and byte tables", base: wbStaticPage1314Base},
		{name: "pointer table", base: wbStaticPointerTableBase},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wbHashWithMemWriteHook(tc.data, func(addr uint64, n int) {
				for _, page := range inlinedPages {
					if writeOverlapsStaticPage(addr, n, page.base) {
						t.Errorf("write to inlined %s page: addr=0x%x n=%d", page.name, addr, n)
					}
				}
			})
			if err != nil {
				t.Fatalf("WBHash failed: %v", err)
			}
		})
	}
}

func snapshotPageForTest(t *testing.T, wantBase uint64) []byte {
	t.Helper()

	data := snapshotData
	pos := 0
	nPages := binary.LittleEndian.Uint32(data[pos:])
	pos += 4 + 8 + 8

	for {
		addr := binary.LittleEndian.Uint64(data[pos:])
		pos += 8
		if addr == 0 {
			break
		}
		nameLen := int(binary.LittleEndian.Uint16(data[pos:]))
		pos += 2 + nameLen
	}

	for page := uint32(0); page < nPages; page++ {
		addr := binary.LittleEndian.Uint64(data[pos:])
		pos += 8
		pageData := data[pos : pos+int(wbStaticPageSize)]
		pos += int(wbStaticPageSize)
		if addr == wantBase {
			return pageData
		}
	}

	t.Fatalf("snapshot page 0x%x not found", wantBase)
	return nil
}

func writeOverlapsStaticPage(addr uint64, n int, pageBase uint64) bool {
	if n <= 0 {
		return false
	}
	end := addr + uint64(n)
	return addr < pageBase+wbStaticPageSize && end > pageBase
}
