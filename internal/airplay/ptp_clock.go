package airplay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// AirPlay 2 uses the IEEE 802.1AS (gPTP) profile over UDP 319/320.  A single
// sender clock is shared by every PTP receiver in an audio group; running one
// clock per receiver would advertise competing grandmasters and destroy the
// common media timeline.
// AirPlay's ClockPorts map identifies logical PTP ports in the packet header.
// Apple TimeSync uses it for receive matching within the UDP transport.
const (
	ptpEventPort   = 319
	ptpGeneralPort = 320
	ptpHeaderSize  = 34

	ptpMessageSync                     = 0x0
	ptpMessageDelayRequest             = 0x1
	ptpMessagePDelayRequest            = 0x2
	ptpMessagePDelayResponse           = 0x3
	ptpMessageFollowUp                 = 0x8
	ptpMessageDelayResponse            = 0x9
	ptpMessagePDelayResponseFUP        = 0xa
	ptpMessageAnnounce                 = 0xb
	ptpMessageSignaling                = 0xc
	ptpTLVRequestUnicast               = 0x0004
	ptpTLVGrantUnicast                 = 0x0005
	ptpFlagTwoStep              uint16 = 0x0200
	ptpFlagUnicast              uint16 = 0x0400
	ptpFlagTimescale            uint16 = 0x0008

	ptpSyncInterval     = 125 * time.Millisecond
	ptpAnnounceInterval = time.Second
	ptpExchangeGap      = 3 * time.Second
	// Give the peer time to establish its clock before announcing playout.
	// Successful exchanges are a readiness heuristic; the remote servo
	// state is unavailable to the sender.
	ptpClockLockInterval = 2300 * time.Millisecond
)

type ptpPeerExchange struct {
	first time.Time
	last  time.Time
	count uint32
}

type sharedPTPClock struct {
	clockID uint64
	groupID string
	epoch   time.Time
	event   *net.UDPConn
	general *net.UDPConn

	peerEventPort, peerGeneralPort uint16

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	txMu        sync.Mutex
	mu          sync.RWMutex
	peers       map[netip.Addr]int
	exchanges   map[netip.Addr]ptpPeerExchange
	syncSeq     uint16
	announceSeq uint16
	signalSeq   uint16
	closeErr    error
	closeOnce   sync.Once
}

// A process shares one grandmaster and binds the standard ports exclusively.
type ptpClockPool struct {
	mu                             sync.Mutex
	clock                          *sharedPTPClock
	users                          int
	bind                           func() (*net.UDPConn, *net.UDPConn, error)
	peerEventPort, peerGeneralPort uint16
}

var directAudioPTP = ptpClockPool{bind: bindPTPClock}

func bindPTPClock() (*net.UDPConn, *net.UDPConn, error) {
	event, err := net.ListenUDP("udp", &net.UDPAddr{Port: ptpEventPort})
	if err != nil {
		return nil, nil, fmt.Errorf("bind PTP event port UDP %d: %w", ptpEventPort, err)
	}
	general, err := net.ListenUDP("udp", &net.UDPAddr{Port: ptpGeneralPort})
	if err != nil {
		_ = event.Close()
		return nil, nil, fmt.Errorf("bind PTP general port UDP %d: %w", ptpGeneralPort, err)
	}
	return event, general, nil
}

func (pool *ptpClockPool) acquire(peer netip.Addr) (*sharedPTPClock, func(), error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.clock == nil {
		var id [8]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, nil, err
		}
		event, general, err := pool.bind()
		if err != nil {
			return nil, nil, err
		}
		eventPort, generalPort := pool.peerEventPort, pool.peerGeneralPort
		if eventPort == 0 {
			eventPort = ptpEventPort
		}
		if generalPort == 0 {
			generalPort = ptpGeneralPort
		}
		pool.clock = newSharedPTPClock(binary.BigEndian.Uint64(id[:])|1, event, general, eventPort, generalPort)
	}
	clock := pool.clock
	clock.mu.Lock()
	clock.peers[peer]++
	clock.mu.Unlock()
	pool.users++
	var once sync.Once
	return clock, func() {
		once.Do(func() {
			pool.mu.Lock()
			defer pool.mu.Unlock()
			clock.mu.Lock()
			clock.peers[peer]--
			if clock.peers[peer] == 0 {
				delete(clock.peers, peer)
				delete(clock.exchanges, peer)
			}
			clock.mu.Unlock()
			pool.users--
			if pool.users == 0 {
				_ = clock.Close()
				pool.clock = nil
			}
		})
	}, nil
}

func newSharedPTPClock(clockID uint64, event, general *net.UDPConn, peerEventPort, peerGeneralPort uint16) *sharedPTPClock {
	ctx, cancel := context.WithCancel(context.Background())
	clock := &sharedPTPClock{
		clockID: clockID, groupID: generateUUID(), epoch: time.Now(),
		event: event, general: general, ctx: ctx, cancel: cancel,
		peerEventPort: peerEventPort, peerGeneralPort: peerGeneralPort,
		peers: make(map[netip.Addr]int), exchanges: make(map[netip.Addr]ptpPeerExchange),
	}
	clock.wg.Add(4)
	go clock.periodic()
	go clock.receive(event)
	go clock.receive(general)
	go clock.closeOnContextDone()
	return clock
}

func (clock *sharedPTPClock) closeOnContextDone() {
	defer clock.wg.Done()
	<-clock.ctx.Done()
	if err := clock.event.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		clock.mu.Lock()
		clock.closeErr = err
		clock.mu.Unlock()
	}
	if err := clock.general.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		clock.mu.Lock()
		if clock.closeErr == nil {
			clock.closeErr = err
		}
		clock.mu.Unlock()
	}
}

func (clock *sharedPTPClock) nanosecondsAt(t time.Time) uint64 {
	return uint64(clock.epoch.UnixNano() + int64(t.Sub(clock.epoch)))
}

func (clock *sharedPTPClock) NowNanoseconds() uint64 {
	return clock.nanosecondsAt(time.Now())
}

func (clock *sharedPTPClock) mediaTimeAt(t time.Time) (uint64, uint64) {
	if t.IsZero() {
		t = time.Now()
	}
	return compactTimestamp(time.Duration(clock.nanosecondsAt(t))), clock.clockID
}

func (clock *sharedPTPClock) WaitPeerReady(ctx context.Context, peer netip.Addr) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		clock.mu.RLock()
		exchange, ok := clock.exchanges[peer]
		clock.mu.RUnlock()
		if err := ctx.Err(); err != nil {
			if ok {
				return fmt.Errorf("PTP peer %s produced %d of 3 required timing exchanges: %w", peer, exchange.count, err)
			}
			return fmt.Errorf("PTP peer %s produced no timing exchanges: %w", peer, err)
		}
		if clock.ctx.Err() != nil {
			return errors.New("PTP clock closed")
		}
		if ok && exchange.count >= 3 && time.Since(exchange.first) >= ptpClockLockInterval && time.Since(exchange.last) <= ptpExchangeGap {
			return nil
		}
		select {
		case <-ctx.Done():
		case <-clock.ctx.Done():
		case <-ticker.C:
		}
	}
}

func (clock *sharedPTPClock) periodic() {
	defer clock.wg.Done()
	clock.sendAnnounce()
	clock.sendSignaling()
	clock.sendSync()
	syncTicker := time.NewTicker(ptpSyncInterval)
	announceTicker := time.NewTicker(ptpAnnounceInterval)
	defer syncTicker.Stop()
	defer announceTicker.Stop()
	for {
		select {
		case <-clock.ctx.Done():
			return
		case <-syncTicker.C:
			clock.sendSync()
		case <-announceTicker.C:
			clock.sendAnnounce()
			clock.sendSignaling()
		}
	}
}

func (clock *sharedPTPClock) peersSnapshot() []netip.Addr {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	peers := make([]netip.Addr, 0, len(clock.peers))
	for ip := range clock.peers {
		peers = append(peers, ip)
	}
	return peers
}

func (clock *sharedPTPClock) sendPacket(conn *net.UDPConn, port uint16, packet []byte, peers []netip.Addr) {
	for _, ip := range peers {
		if _, err := conn.WriteToUDPAddrPort(packet, netip.AddrPortFrom(ip, port)); err != nil && clock.ctx.Err() == nil {
			dbg("[PTP] send to %s:%d failed: %v", ip, port, err)
		}
	}
}

func (clock *sharedPTPClock) sendToPeers(conn *net.UDPConn, port uint16, packet []byte) {
	clock.sendPacket(conn, port, packet, clock.peersSnapshot())
}

func ptpHeader(messageType byte, length int, flags uint16, clockID uint64, sequence uint16, control byte, logInterval int8) []byte {
	header := make([]byte, ptpHeaderSize)
	header[0] = 0x10 | messageType // majorSdoId=1 is mandatory for gPTP.
	header[1] = 0x02
	binary.BigEndian.PutUint16(header[2:4], uint16(length))
	header[4] = 0
	binary.BigEndian.PutUint16(header[6:8], flags)
	binary.BigEndian.PutUint64(header[20:28], clockID)
	binary.BigEndian.PutUint16(header[28:30], 0x8005)
	binary.BigEndian.PutUint16(header[30:32], sequence)
	header[32] = control
	header[33] = byte(logInterval)
	return header
}

func writePTPTimestamp(dst []byte, nanoseconds uint64) {
	seconds := nanoseconds / uint64(time.Second)
	nanos := uint32(nanoseconds % uint64(time.Second))
	dst[0] = byte(seconds >> 40)
	dst[1] = byte(seconds >> 32)
	dst[2] = byte(seconds >> 24)
	dst[3] = byte(seconds >> 16)
	dst[4] = byte(seconds >> 8)
	dst[5] = byte(seconds)
	binary.BigEndian.PutUint32(dst[6:10], nanos)
}

func buildPTPAnnounce(clockID uint64, sequence uint16) []byte {
	packet := make([]byte, ptpHeaderSize+30+12)
	copy(packet, ptpHeader(ptpMessageAnnounce, len(packet), ptpFlagUnicast|ptpFlagTimescale, clockID, sequence, 0, 0))
	body := packet[ptpHeaderSize:]
	body[13] = 128
	body[14] = 6
	body[15] = 0x21
	binary.BigEndian.PutUint16(body[16:18], 0x436a)
	body[18] = 128
	binary.BigEndian.PutUint64(body[19:27], clockID)
	body[29] = 0x20
	binary.BigEndian.PutUint16(body[30:32], 0x0008) // PATH_TRACE
	binary.BigEndian.PutUint16(body[32:34], 8)
	binary.BigEndian.PutUint64(body[34:42], clockID)
	return packet
}

func buildPTPSync(clockID uint64, sequence uint16) []byte {
	packet := make([]byte, ptpHeaderSize+10)
	copy(packet, ptpHeader(ptpMessageSync, len(packet), ptpFlagUnicast|ptpFlagTimescale|ptpFlagTwoStep, clockID, sequence, 0, -3))
	return packet
}

func buildPTPFollowUp(clockID uint64, sequence uint16, egress uint64) []byte {
	packet := make([]byte, ptpHeaderSize+10+32+20)
	copy(packet, ptpHeader(ptpMessageFollowUp, len(packet), ptpFlagUnicast|ptpFlagTimescale, clockID, sequence, 0, -3))
	writePTPTimestamp(packet[ptpHeaderSize:ptpHeaderSize+10], egress)
	tlv := packet[ptpHeaderSize+10:]
	binary.BigEndian.PutUint16(tlv[0:2], 0x0003)
	binary.BigEndian.PutUint16(tlv[2:4], 28)
	copy(tlv[4:10], []byte{0x00, 0x80, 0xc2, 0x00, 0x00, 0x01})
	tlv = tlv[32:]
	binary.BigEndian.PutUint16(tlv[0:2], 0x0003)
	binary.BigEndian.PutUint16(tlv[2:4], 16)
	copy(tlv[4:10], []byte{0x00, 0x0d, 0x93, 0x00, 0x00, 0x04})
	binary.BigEndian.PutUint64(tlv[10:18], clockID)
	return packet
}

func buildPTPSignaling(clockID uint64, sequence uint16) []byte {
	packet := make([]byte, ptpHeaderSize+10+26+36)
	copy(packet, ptpHeader(ptpMessageSignaling, len(packet), ptpFlagUnicast|ptpFlagTimescale, clockID, sequence, 5, -128))
	tlv := packet[ptpHeaderSize+10:]
	binary.BigEndian.PutUint16(tlv[0:2], 0x0003)
	binary.BigEndian.PutUint16(tlv[2:4], 22)
	copy(tlv[4:14], []byte{0x00, 0x0d, 0x93, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x01})
	tlv = tlv[26:]
	binary.BigEndian.PutUint16(tlv[0:2], 0x0003)
	binary.BigEndian.PutUint16(tlv[2:4], 32)
	copy(tlv[4:14], []byte{0x00, 0x0d, 0x93, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0x01})
	return packet
}

func (clock *sharedPTPClock) sendAnnounce() {
	clock.txMu.Lock()
	defer clock.txMu.Unlock()
	clock.mu.Lock()
	sequence := clock.announceSeq
	clock.announceSeq++
	clock.mu.Unlock()
	clock.sendToPeers(clock.general, clock.peerGeneralPort, buildPTPAnnounce(clock.clockID, sequence))
}

func (clock *sharedPTPClock) sendSync() {
	// Keep each two-step Sync/Follow_Up pair contiguous and send both halves to
	// the same peer snapshot so a newly connected peer cannot receive a
	// Follow_Up without its matching Sync.
	clock.txMu.Lock()
	defer clock.txMu.Unlock()
	clock.mu.Lock()
	sequence := clock.syncSeq
	clock.syncSeq++
	clock.mu.Unlock()
	peers := clock.peersSnapshot()
	clock.sendPacket(clock.event, clock.peerEventPort, buildPTPSync(clock.clockID, sequence), peers)
	egress := clock.NowNanoseconds()
	clock.sendPacket(clock.general, clock.peerGeneralPort, buildPTPFollowUp(clock.clockID, sequence, egress), peers)
}

func (clock *sharedPTPClock) sendSignaling() {
	clock.txMu.Lock()
	defer clock.txMu.Unlock()
	clock.mu.Lock()
	sequence := clock.signalSeq
	clock.signalSeq++
	clock.mu.Unlock()
	clock.sendToPeers(clock.general, clock.peerGeneralPort, buildPTPSignaling(clock.clockID, sequence))
}

func (clock *sharedPTPClock) receive(conn *net.UDPConn) {
	defer clock.wg.Done()
	buffer := make([]byte, 512)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if clock.ctx.Err() != nil {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			dbg("[PTP] receive failed: %v", err)
			return
		}
		packet, ok := validatedPTPPacket(buffer[:n])
		if !ok || binary.BigEndian.Uint64(packet[20:28]) == clock.clockID {
			continue
		}
		peer := source.AddrPort().Addr().Unmap()
		clock.mu.RLock()
		known := clock.peers[peer] != 0
		clock.mu.RUnlock()
		if !known {
			continue
		}
		messageType := packet[0] & 0x0f
		switch messageType {
		case ptpMessageDelayRequest:
			if clock.sendDelayResponse(packet, source, clock.NowNanoseconds()) {
				clock.trackExchange(peer)
			}
		case ptpMessagePDelayRequest:
			if clock.sendPDelayResponse(packet, source, clock.NowNanoseconds()) {
				clock.trackExchange(peer)
			}
		case ptpMessageSignaling:
			clock.grantUnicast(packet, source)
		}
	}
}

// validatedPTPPacket applies only structural checks. In particular, it does
// not reject a receiver that sends transportSpecific=0 rather than the gPTP
// value 1: some compatible third-party stacks probe with plain IEEE 1588
// headers even though they accept the sender's 802.1AS packets.
func validatedPTPPacket(packet []byte) ([]byte, bool) {
	if len(packet) < ptpHeaderSize || packet[1]&0x0f != 2 {
		return nil, false
	}
	declared := int(binary.BigEndian.Uint16(packet[2:4]))
	if declared < ptpHeaderSize || declared > len(packet) {
		return nil, false
	}
	return packet[:declared], true
}

func (clock *sharedPTPClock) trackExchange(peer netip.Addr) {
	now := time.Now()
	clock.mu.Lock()
	// Ignore unrelated multicast-domain traffic. Besides avoiding readiness
	// false positives, this bounds the exchange table to the explicitly selected
	// target set instead of letting arbitrary LAN senders grow it indefinitely.
	if _, known := clock.peers[peer]; !known {
		clock.mu.Unlock()
		return
	}
	exchange := clock.exchanges[peer]
	if exchange.last.IsZero() || now.Sub(exchange.last) > ptpExchangeGap || now.Before(exchange.last) {
		exchange = ptpPeerExchange{first: now, count: 1}
	} else if exchange.count < ^uint32(0) {
		exchange.count++
	}
	exchange.last = now
	clock.exchanges[peer] = exchange
	clock.mu.Unlock()
}

func buildPTPTimedResponse(messageType byte, clockID uint64, sequence uint16, timestamp uint64, requester []byte) []byte {
	packet := make([]byte, ptpHeaderSize+20)
	flags := ptpFlagUnicast | ptpFlagTimescale
	if messageType != ptpMessagePDelayResponseFUP {
		flags |= ptpFlagTwoStep
	}
	copy(packet, ptpHeader(messageType, len(packet), flags, clockID, sequence, 0, -3))
	writePTPTimestamp(packet[ptpHeaderSize:ptpHeaderSize+10], timestamp)
	copy(packet[ptpHeaderSize+10:], requester)
	return packet
}

func (clock *sharedPTPClock) sendDelayResponse(request []byte, source *net.UDPAddr, received uint64) bool {
	if len(request) < ptpHeaderSize+10 {
		return false
	}
	clock.txMu.Lock()
	defer clock.txMu.Unlock()
	sequence := binary.BigEndian.Uint16(request[30:32])
	packet := buildPTPTimedResponse(ptpMessageDelayResponse, clock.clockID, sequence, received, request[20:30])
	_, err := clock.general.WriteToUDP(packet, &net.UDPAddr{IP: source.IP, Zone: source.Zone, Port: int(clock.peerGeneralPort)})
	return err == nil
}

func (clock *sharedPTPClock) sendPDelayResponse(request []byte, source *net.UDPAddr, received uint64) bool {
	if len(request) < ptpHeaderSize+10 {
		return false
	}
	clock.txMu.Lock()
	defer clock.txMu.Unlock()
	sequence := binary.BigEndian.Uint16(request[30:32])
	response := buildPTPTimedResponse(ptpMessagePDelayResponse, clock.clockID, sequence, received, request[20:30])
	if _, err := clock.event.WriteToUDP(response, &net.UDPAddr{IP: source.IP, Zone: source.Zone, Port: int(clock.peerEventPort)}); err != nil {
		return false
	}

	followUp := buildPTPTimedResponse(ptpMessagePDelayResponseFUP, clock.clockID, sequence, clock.NowNanoseconds(), request[20:30])
	_, err := clock.general.WriteToUDP(followUp, &net.UDPAddr{IP: source.IP, Zone: source.Zone, Port: int(clock.peerGeneralPort)})
	return err == nil
}

func buildPTPUnicastGrant(request []byte, clockID uint64) ([]byte, bool) {
	offset := ptpHeaderSize + 10
	if len(request) < offset+4 {
		return nil, false
	}
	grants := make([]byte, 0, 8*12)
	for offset+4 <= len(request) && len(grants) < 8*12 {
		tlvType := binary.BigEndian.Uint16(request[offset : offset+2])
		length := int(binary.BigEndian.Uint16(request[offset+2 : offset+4]))
		if offset+4+length > len(request) {
			return nil, false
		}
		value := request[offset+4 : offset+4+length]
		if tlvType == ptpTLVRequestUnicast && len(value) >= 6 {
			duration := binary.BigEndian.Uint32(value[2:6])
			if duration == 0 {
				duration = 300
			}
			grant := make([]byte, 12)
			binary.BigEndian.PutUint16(grant[0:2], ptpTLVGrantUnicast)
			binary.BigEndian.PutUint16(grant[2:4], 8)
			grant[4] = value[0] & 0xf0
			grant[5] = value[1]
			binary.BigEndian.PutUint32(grant[6:10], duration)
			grant[11] = 1
			grants = append(grants, grant...)
		}
		offset += 4 + length
	}
	if len(grants) == 0 {
		return nil, false
	}
	sequence := binary.BigEndian.Uint16(request[30:32])
	reply := make([]byte, ptpHeaderSize+10+len(grants))
	copy(reply, ptpHeader(ptpMessageSignaling, len(reply), ptpFlagUnicast, clockID, sequence, 5, 0x7f))
	copy(reply[ptpHeaderSize:ptpHeaderSize+10], request[20:30])
	copy(reply[ptpHeaderSize+10:], grants)
	return reply, true
}

func (clock *sharedPTPClock) grantUnicast(request []byte, source *net.UDPAddr) {
	reply, ok := buildPTPUnicastGrant(request, clock.clockID)
	if !ok {
		return
	}
	clock.txMu.Lock()
	defer clock.txMu.Unlock()
	_, _ = clock.general.WriteToUDP(reply, &net.UDPAddr{IP: source.IP, Zone: source.Zone, Port: int(clock.peerGeneralPort)})
}

func (clock *sharedPTPClock) Close() error {
	if clock == nil {
		return nil
	}
	clock.closeOnce.Do(func() {
		clock.cancel()
		clock.wg.Wait()
	})
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.closeErr
}
