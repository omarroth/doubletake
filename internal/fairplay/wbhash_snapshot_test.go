package fairplay

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

var wbHashOmittedSnapshotPages = []uint64{
	0x1806ed000, 0x1807d4000,
	0x1a12a2000, 0x1a12a3000, 0x1a12a4000, 0x1a12a5000,
	0x1a12a6000, 0x1a12ae000, 0x1a12af000, 0x1a12b9000,
	0x1a12ba000, 0x1a12bd000, 0x1a12bf000, 0x1a12c0000,
	0x1a12c1000, 0x1a12c2000, 0x1a12c3000, 0x1a12c4000, 0x1a12c5000,
	0x1a12c6000, 0x1a12c8000, 0x1a12cb000, 0x1a12cc000,
	0x1a12cd000, 0x1a12ce000, 0x1a12cf000, 0x1a12d0000,
	0x1a12d1000, 0x1a12d3000, 0x1a12d4000, 0x1a12d5000,
	0x1a12d6000, 0x1a12d7000, 0x1a12d8000, 0x1a12d9000, 0x1a1305000,
	0x1a1306000, 0x1a1307000, 0x1a1308000, 0x1a1309000, 0x1a130a000,
	0x1a130c000, 0x1a130d000, 0x1a130e000,
	0x1a1311000,
	0x1a1314000,
	0x1aeaaf000,
}

func TestWBHashSnapshotOmitsColdPages(t *testing.T) {
	snapshotPages := snapshotPageBasesForTest(t)
	for _, page := range wbHashOmittedSnapshotPages {
		if snapshotPages[page] {
			t.Errorf("cold page 0x%x is still embedded in snapshotData", page)
		}
	}
}

func TestWBHashOmittedSnapshotPagesStayUnread(t *testing.T) {
	omitted := make(map[uint64]bool, len(wbHashOmittedSnapshotPages))
	for _, page := range wbHashOmittedSnapshotPages {
		omitted[page] = true
	}

	for _, tc := range wbHashProofPayloadsForTest() {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wbHashWithMemReadHook(tc.data, func(addr uint64, n int) {
				for _, page := range pagesOverlappingRange(addr, n) {
					if omitted[page] {
						t.Errorf("read from omitted snapshot page 0x%x: addr=0x%x n=%d", page, addr, n)
					}
				}
			})
			if err != nil {
				t.Fatalf("WBHash failed: %v", err)
			}
		})
	}
}

func TestWBHashSnapshotReadPagesForAnalysis(t *testing.T) {
	if os.Getenv("WBHASH_TRACE_SNAPSHOT_READS") == "" {
		t.Skip("set WBHASH_TRACE_SNAPSHOT_READS=1 to log snapshot page reads")
	}

	snapshotPages := snapshotPageBasesForTest(t)
	readPages := make(map[uint64]bool)
	for _, tc := range wbHashProofPayloadsForTest() {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wbHashWithMemReadHook(tc.data, func(addr uint64, n int) {
				for _, page := range pagesOverlappingRange(addr, n) {
					if snapshotPages[page] {
						readPages[page] = true
					}
				}
			})
			if err != nil {
				t.Fatalf("WBHash failed: %v", err)
			}
		})
	}

	var unread []uint64
	for page := range snapshotPages {
		if !readPages[page] {
			unread = append(unread, page)
		}
	}
	sort.Slice(unread, func(i, j int) bool { return unread[i] < unread[j] })
	t.Logf("read snapshot pages: %d/%d", len(readPages), len(snapshotPages))
	t.Logf("unread snapshot pages: %s", formatHexPagesForTest(unread))
}

func TestWBHashSnapshotReadRangesForAnalysis(t *testing.T) {
	if os.Getenv("WBHASH_TRACE_SNAPSHOT_RANGES") == "" {
		t.Skip("set WBHASH_TRACE_SNAPSHOT_RANGES=1 to log snapshot byte ranges")
	}

	snapshotPages := snapshotPageBasesForTest(t)
	rangesByPage := make(map[uint64][]wbHashReadRange)
	readsByPage := make(map[uint64]int)
	for _, tc := range wbHashProofPayloadsForTest() {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wbHashWithMemReadHook(tc.data, func(addr uint64, n int) {
				for _, page := range pagesOverlappingRange(addr, n) {
					if !snapshotPages[page] {
						continue
					}
					start := max(addr, page)
					end := min(addr+uint64(n), page+wbStaticPageSize)
					rangesByPage[page] = append(rangesByPage[page], wbHashReadRange{start: start - page, end: end - page})
					readsByPage[page]++
				}
			})
			if err != nil {
				t.Fatalf("WBHash failed: %v", err)
			}
		})
	}

	pages := make([]uint64, 0, len(rangesByPage))
	for page := range rangesByPage {
		pages = append(pages, page)
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i] < pages[j] })
	for _, page := range pages {
		merged := mergeWBHashReadRanges(rangesByPage[page])
		t.Logf("page 0x%x: reads=%d merged=%d bytes=%d ranges=%s", page, readsByPage[page], len(merged), wbHashReadRangeBytes(merged), formatWBHashReadRanges(merged))
	}
}

func TestWBHashSnapshotReadPCsForAnalysis(t *testing.T) {
	if os.Getenv("WBHASH_TRACE_SNAPSHOT_READ_PCS") == "" {
		t.Skip("set WBHASH_TRACE_SNAPSHOT_READ_PCS=1 to log snapshot reads by pc")
	}

	snapshotPages := snapshotPageBasesForTest(t)
	rangesBySource := make(map[wbHashReadSource][]wbHashReadRange)
	readsBySource := make(map[wbHashReadSource]int)
	for _, tc := range wbHashProofPayloadsForTest() {
		t.Run(tc.name, func(t *testing.T) {
			_, err := wbHashWithMemReadPCHook(tc.data, func(pc, addr uint64, n int) {
				for _, page := range pagesOverlappingRange(addr, n) {
					if !snapshotPages[page] {
						continue
					}
					start := max(addr, page)
					end := min(addr+uint64(n), page+wbStaticPageSize)
					source := wbHashReadSource{page: page, pc: pc}
					rangesBySource[source] = append(rangesBySource[source], wbHashReadRange{start: start - page, end: end - page})
					readsBySource[source]++
				}
			})
			if err != nil {
				t.Fatalf("WBHash failed: %v", err)
			}
		})
	}

	sources := make([]wbHashReadSource, 0, len(rangesBySource))
	for source := range rangesBySource {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].page == sources[j].page {
			return sources[i].pc < sources[j].pc
		}
		return sources[i].page < sources[j].page
	})
	for _, source := range sources {
		merged := mergeWBHashReadRanges(rangesBySource[source])
		t.Logf("page 0x%x pc 0x%x: reads=%d merged=%d bytes=%d ranges=%s", source.page, source.pc, readsBySource[source], len(merged), wbHashReadRangeBytes(merged), formatWBHashReadRanges(merged))
	}
}

func TestWBHashSnapshotSlotsForAnalysis(t *testing.T) {
	if os.Getenv("WBHASH_TRACE_SNAPSHOT_SLOTS") == "" {
		t.Skip("set WBHASH_TRACE_SNAPSHOT_SLOTS=1 to log selected snapshot slots")
	}

	for _, addr := range []uint64{0x1aeaaf398} {
		if !snapshotPageBasesForTest(t)[addr&^(wbStaticPageSize-1)] {
			t.Logf("slot 0x%x is omitted from snapshotData", addr)
			continue
		}
		value := snapshotUint64ForTest(t, addr)
		t.Logf("slot 0x%x = 0x%x", addr, value)
		if value != 0 {
			page := value &^ (wbStaticPageSize - 1)
			if snapshotPageBasesForTest(t)[page] {
				t.Logf("slot 0x%x target[0] = 0x%x", addr, snapshotUint64ForTest(t, value))
			}
		}
	}
}

type wbHashReadRange struct {
	start uint64
	end   uint64
}

type wbHashReadSource struct {
	page uint64
	pc   uint64
}

func wbHashProofPayloadsForTest() []struct {
	name string
	data [128]byte
} {
	return []struct {
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
}

func snapshotPageBasesForTest(t *testing.T) map[uint64]bool {
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

	pages := make(map[uint64]bool, nPages)
	for page := uint32(0); page < nPages; page++ {
		addr := binary.LittleEndian.Uint64(data[pos:])
		pos += 8 + int(wbStaticPageSize)
		pages[addr] = true
	}
	return pages
}

func snapshotUint64ForTest(t *testing.T, addr uint64) uint64 {
	t.Helper()

	page := snapshotPageForTest(t, addr&^(wbStaticPageSize-1))
	off := int(addr & (wbStaticPageSize - 1))
	return binary.LittleEndian.Uint64(page[off:])
}

func pagesOverlappingRange(addr uint64, n int) []uint64 {
	if n <= 0 {
		return nil
	}
	start := addr &^ (wbStaticPageSize - 1)
	end := (addr + uint64(n) - 1) &^ (wbStaticPageSize - 1)
	pages := make([]uint64, 0, (end-start)/wbStaticPageSize+1)
	for page := start; page <= end; page += wbStaticPageSize {
		pages = append(pages, page)
	}
	return pages
}

func formatHexPagesForTest(pages []uint64) string {
	if len(pages) == 0 {
		return "(none)"
	}
	parts := make([]string, len(pages))
	for i, page := range pages {
		parts[i] = fmt.Sprintf("0x%x", page)
	}
	return strings.Join(parts, ", ")
}

func mergeWBHashReadRanges(ranges []wbHashReadRange) []wbHashReadRange {
	if len(ranges) == 0 {
		return nil
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})

	merged := []wbHashReadRange{ranges[0]}
	for _, next := range ranges[1:] {
		last := &merged[len(merged)-1]
		if next.start <= last.end {
			if next.end > last.end {
				last.end = next.end
			}
			continue
		}
		merged = append(merged, next)
	}
	return merged
}

func wbHashReadRangeBytes(ranges []wbHashReadRange) uint64 {
	var total uint64
	for _, readRange := range ranges {
		total += readRange.end - readRange.start
	}
	return total
}

func formatWBHashReadRanges(ranges []wbHashReadRange) string {
	if len(ranges) == 0 {
		return "(none)"
	}
	parts := make([]string, len(ranges))
	for i, readRange := range ranges {
		parts[i] = fmt.Sprintf("0x%03x..0x%03x", readRange.start, readRange.end)
	}
	return strings.Join(parts, ", ")
}


