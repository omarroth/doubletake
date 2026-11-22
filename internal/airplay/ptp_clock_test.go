package airplay

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func readPTPTimestamp(src []byte) uint64 {
	seconds := uint64(src[0])<<40 |
		uint64(src[1])<<32 |
		uint64(src[2])<<24 |
		uint64(src[3])<<16 |
		uint64(src[4])<<8 |
		uint64(src[5])
	return seconds*uint64(time.Second) + uint64(binary.BigEndian.Uint32(src[6:10]))
}

func requirePTPHeader(t *testing.T, packet []byte, messageType byte, length int, flags uint16, clockID uint64, sequence uint16, control byte, logInterval int8) {
	t.Helper()
	if len(packet) != length {
		t.Fatalf("packet length = %d, want %d", len(packet), length)
	}
	if packet[0] != 0x10|messageType {
		t.Errorf("transportSpecific/messageType = 0x%02x, want 0x%02x", packet[0], 0x10|messageType)
	}
	if packet[1] != 2 {
		t.Errorf("versionPTP = 0x%02x, want 0x02", packet[1])
	}
	if got := int(binary.BigEndian.Uint16(packet[2:4])); got != length {
		t.Errorf("messageLength = %d, want %d", got, length)
	}
	if packet[4] != 0 || packet[5] != 0 {
		t.Errorf("domain/reserved = %02x %02x, want zero", packet[4], packet[5])
	}
	if got := binary.BigEndian.Uint16(packet[6:8]); got != flags {
		t.Errorf("flags = 0x%04x, want 0x%04x", got, flags)
	}
	if !bytes.Equal(packet[8:20], make([]byte, 12)) {
		t.Errorf("correction/reserved fields are nonzero: %x", packet[8:20])
	}
	if got := binary.BigEndian.Uint64(packet[20:28]); got != clockID {
		t.Errorf("source clock identity = 0x%016x, want 0x%016x", got, clockID)
	}
	if got := binary.BigEndian.Uint16(packet[28:30]); got != 0x8005 {
		t.Errorf("source port = 0x%04x, want 0x8005", got)
	}
	if got := binary.BigEndian.Uint16(packet[30:32]); got != sequence {
		t.Errorf("sequence = 0x%04x, want 0x%04x", got, sequence)
	}
	if packet[32] != control || packet[33] != byte(logInterval) {
		t.Errorf("control/log interval = %02x/%02x, want %02x/%02x", packet[32], packet[33], control, byte(logInterval))
	}
}

func TestPTPAnnounceWireFormat(t *testing.T) {
	const clockID = uint64(0x0102030405060708)
	packet := buildPTPAnnounce(clockID, 0x1122)
	requirePTPHeader(t, packet, ptpMessageAnnounce, 76, ptpFlagUnicast|ptpFlagTimescale, clockID, 0x1122, 0, 0)

	body := packet[ptpHeaderSize:]
	if !bytes.Equal(body[:13], make([]byte, 13)) {
		t.Errorf("announce timestamp/UTC/reserved prefix = %x, want zero", body[:13])
	}
	if got := body[13:19]; !bytes.Equal(got, []byte{128, 6, 0x21, 0x43, 0x6a, 128}) {
		t.Errorf("announce clock quality = %x", got)
	}
	if got := binary.BigEndian.Uint64(body[19:27]); got != clockID {
		t.Errorf("grandmaster identity = 0x%016x", got)
	}
	if body[27] != 0 || body[28] != 0 || body[29] != 0x20 {
		t.Errorf("steps/time source = %x, want 000020", body[27:30])
	}
	if got := binary.BigEndian.Uint16(body[30:32]); got != 0x0008 {
		t.Errorf("path trace TLV type = 0x%04x", got)
	}
	if got := binary.BigEndian.Uint16(body[32:34]); got != 8 {
		t.Errorf("path trace TLV length = %d", got)
	}
	if got := binary.BigEndian.Uint64(body[34:42]); got != clockID {
		t.Errorf("path trace clock identity = 0x%016x", got)
	}
}

func TestPTPSyncFollowUpWireFormat(t *testing.T) {
	const (
		clockID  = uint64(0x1020304050607080)
		sequence = uint16(0xa1b2)
		seconds  = uint64(0x0102030405)
		nanos    = uint64(0x11223344)
	)
	syncPacket := buildPTPSync(clockID, sequence)
	requirePTPHeader(t, syncPacket, ptpMessageSync, 44, ptpFlagUnicast|ptpFlagTimescale|ptpFlagTwoStep, clockID, sequence, 0, -3)
	if !bytes.Equal(syncPacket[ptpHeaderSize:], make([]byte, 10)) {
		t.Errorf("two-step Sync originTimestamp = %x, want zero", syncPacket[ptpHeaderSize:])
	}

	timestamp := seconds*uint64(time.Second) + nanos
	followUp := buildPTPFollowUp(clockID, sequence, timestamp)
	requirePTPHeader(t, followUp, ptpMessageFollowUp, 96, ptpFlagUnicast|ptpFlagTimescale, clockID, sequence, 0, -3)
	if got := readPTPTimestamp(followUp[ptpHeaderSize : ptpHeaderSize+10]); got != timestamp {
		t.Errorf("preciseOriginTimestamp = %d, want %d", got, timestamp)
	}

	first := followUp[44:76]
	if binary.BigEndian.Uint16(first[0:2]) != 0x0003 || binary.BigEndian.Uint16(first[2:4]) != 28 {
		t.Errorf("802.1AS Follow_Up TLV header = %x", first[:4])
	}
	if !bytes.Equal(first[4:10], []byte{0x00, 0x80, 0xc2, 0x00, 0x00, 0x01}) {
		t.Errorf("802.1AS Follow_Up OUI/subtype = %x", first[4:10])
	}
	if !bytes.Equal(first[10:], make([]byte, 22)) {
		t.Errorf("802.1AS Follow_Up body = %x, want zero", first[10:])
	}

	apple := followUp[76:96]
	if binary.BigEndian.Uint16(apple[0:2]) != 0x0003 || binary.BigEndian.Uint16(apple[2:4]) != 16 {
		t.Errorf("Apple Follow_Up TLV header = %x", apple[:4])
	}
	if !bytes.Equal(apple[4:10], []byte{0x00, 0x0d, 0x93, 0x00, 0x00, 0x04}) {
		t.Errorf("Apple Follow_Up OUI/subtype = %x", apple[4:10])
	}
	if got := binary.BigEndian.Uint64(apple[10:18]); got != clockID {
		t.Errorf("Apple Follow_Up clock identity = 0x%016x", got)
	}
	if apple[18] != 0 || apple[19] != 0 {
		t.Errorf("Apple Follow_Up padding = %x, want zero", apple[18:])
	}
}

func TestPTPSignalingWireFormat(t *testing.T) {
	const clockID = uint64(0x8877665544332211)
	packet := buildPTPSignaling(clockID, 7)
	requirePTPHeader(t, packet, ptpMessageSignaling, 106, ptpFlagUnicast|ptpFlagTimescale, clockID, 7, 5, -128)
	if !bytes.Equal(packet[ptpHeaderSize:44], make([]byte, 10)) {
		t.Errorf("signaling target identity = %x, want wildcard", packet[ptpHeaderSize:44])
	}
	first, second := packet[44:70], packet[70:106]
	if binary.BigEndian.Uint16(first[:2]) != 3 || binary.BigEndian.Uint16(first[2:4]) != 22 ||
		!bytes.Equal(first[4:14], []byte{0x00, 0x0d, 0x93, 0, 0, 1, 0, 0, 3, 1}) {
		t.Errorf("first Apple signaling TLV = %x", first)
	}
	if binary.BigEndian.Uint16(second[:2]) != 3 || binary.BigEndian.Uint16(second[2:4]) != 32 ||
		!bytes.Equal(second[4:14], []byte{0x00, 0x0d, 0x93, 0, 0, 5, 0, 0, 3, 1}) {
		t.Errorf("second Apple signaling TLV = %x", second)
	}
}

func TestPTPTimedResponseWireFormat(t *testing.T) {
	const (
		clockID   = uint64(0x123456789abcdef0)
		sequence  = uint16(0x3344)
		timestamp = uint64(1_750_000_000_123_456_789)
	)
	requester := []byte{1, 2, 3, 4, 5, 6, 7, 8, 0x80, 5}
	for _, test := range []struct {
		name  string
		type_ byte
		flags uint16
	}{
		{name: "DelayResp", type_: ptpMessageDelayResponse, flags: ptpFlagUnicast | ptpFlagTimescale | ptpFlagTwoStep},
		{name: "PDelayResp", type_: ptpMessagePDelayResponse, flags: ptpFlagUnicast | ptpFlagTimescale | ptpFlagTwoStep},
		{name: "PDelayRespFollowUp", type_: ptpMessagePDelayResponseFUP, flags: ptpFlagUnicast | ptpFlagTimescale},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := buildPTPTimedResponse(test.type_, clockID, sequence, timestamp, requester)
			requirePTPHeader(t, packet, test.type_, 54, test.flags, clockID, sequence, 0, -3)
			if got := readPTPTimestamp(packet[34:44]); got != timestamp {
				t.Errorf("timestamp = %d, want %d", got, timestamp)
			}
			if !bytes.Equal(packet[44:54], requester) {
				t.Errorf("requestingPortIdentity = %x, want %x", packet[44:54], requester)
			}
		})
	}
}

func TestPTPUnicastGrantWireFormat(t *testing.T) {
	const (
		requesterClock = uint64(0x0101010102020202)
		ourClock       = uint64(0xaabbccddeeff0011)
	)
	request := ptpHeader(ptpMessageSignaling, 64, ptpFlagUnicast, requesterClock, 0x7788, 5, 0x7f)
	request = append(request, make([]byte, 10)...)
	request = append(request,
		0x00, 0x04, 0x00, 0x06, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x06, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x0a,
	)
	reply, ok := buildPTPUnicastGrant(request, ourClock)
	if !ok {
		t.Fatal("valid REQUEST_UNICAST TLVs were not granted")
	}
	requirePTPHeader(t, reply, ptpMessageSignaling, 68, ptpFlagUnicast, ourClock, 0x7788, 5, 0x7f)
	if !bytes.Equal(reply[34:44], request[20:30]) {
		t.Errorf("reply target = %x, want request source %x", reply[34:44], request[20:30])
	}
	first, second := reply[44:56], reply[56:68]
	if binary.BigEndian.Uint16(first[:2]) != ptpTLVGrantUnicast || binary.BigEndian.Uint16(first[2:4]) != 8 ||
		first[4] != 0xb0 || first[5] != 0 || binary.BigEndian.Uint32(first[6:10]) != 300 || first[10] != 0 || first[11] != 1 {
		t.Errorf("first GRANT_UNICAST TLV = %x", first)
	}
	if second[4] != 0x00 || second[5] != 0xfd || binary.BigEndian.Uint32(second[6:10]) != 10 || second[11] != 1 {
		t.Errorf("second GRANT_UNICAST TLV = %x", second)
	}

	malformed := append([]byte(nil), request...)
	binary.BigEndian.PutUint16(malformed[46:48], 0x7fff)
	if _, ok := buildPTPUnicastGrant(malformed, ourClock); ok {
		t.Fatal("malformed REQUEST_UNICAST length was accepted")
	}
}

func TestValidatedPTPPacket(t *testing.T) {
	packet := append(ptpHeader(ptpMessageSync, ptpHeaderSize, 0, 1, 2, 0, 0), 0xaa, 0xbb)
	validated, ok := validatedPTPPacket(packet)
	if !ok || len(validated) != ptpHeaderSize {
		t.Fatalf("valid padded packet = (%d, %t), want (%d, true)", len(validated), ok, ptpHeaderSize)
	}

	for name, invalid := range map[string][]byte{
		"short":          make([]byte, ptpHeaderSize-1),
		"wrong version":  append([]byte{0x10, 0x01, 0x00, ptpHeaderSize}, make([]byte, ptpHeaderSize-4)...),
		"short declared": append([]byte{0x10, 0x02, 0x00, ptpHeaderSize - 1}, make([]byte, ptpHeaderSize-4)...),
		"long declared":  append([]byte{0x10, 0x02, 0x00, ptpHeaderSize + 1}, make([]byte, ptpHeaderSize-4)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := validatedPTPPacket(invalid); ok {
				t.Fatal("invalid PTP packet was accepted")
			}
		})
	}

	plainPTP := append([]byte(nil), packet[:ptpHeaderSize]...)
	plainPTP[0] = ptpMessageSync
	if _, ok := validatedPTPPacket(plainPTP); !ok {
		t.Fatal("transportSpecific=0 receiver probe was rejected")
	}
}

func TestPTPExchangeTrackingAndReadiness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := netip.MustParseAddr("192.0.2.20")
	clock := &sharedPTPClock{
		ctx:       ctx,
		peers:     map[netip.Addr]int{peer: 1},
		exchanges: make(map[netip.Addr]ptpPeerExchange),
	}

	clock.trackExchange(netip.MustParseAddr("192.0.2.99"))
	if len(clock.exchanges) != 0 {
		t.Fatalf("unknown peer grew exchange table: %#v", clock.exchanges)
	}
	clock.trackExchange(peer)
	clock.trackExchange(peer)
	clock.trackExchange(peer)
	if got := clock.exchanges[peer].count; got != 3 {
		t.Fatalf("exchange count = %d, want 3", got)
	}

	now := time.Now()
	clock.exchanges[peer] = ptpPeerExchange{
		first: now.Add(-ptpClockLockInterval - time.Millisecond),
		last:  now,
		count: 3,
	}
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer readyCancel()
	if err := clock.WaitPeerReady(readyCtx, peer); err != nil {
		t.Fatalf("settled peer was not ready: %v", err)
	}

	clock.exchanges[peer] = ptpPeerExchange{first: now, last: now, count: 3}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	err := clock.WaitPeerReady(canceled, peer)
	if err == nil || !strings.Contains(err.Error(), "3 of 3 required timing exchanges") {
		t.Fatalf("unsettled peer error = %v", err)
	}
}
