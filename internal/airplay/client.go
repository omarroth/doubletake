package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"howett.net/plist"
)

// ReceiverInfo contains the capabilities returned by GET /info.
type ReceiverInfo struct {
	Name                          string              `plist:"name"`
	Model                         string              `plist:"model"`
	Manufacturer                  string              `plist:"manufacturer"`
	DeviceID                      string              `plist:"deviceID"`
	ProtocolVersion               string              `plist:"protocolVersion"`
	SourceVersion                 string              `plist:"sourceVersion"`
	Server                        string              `plist:"-"`
	VV                            uint64              `plist:"vv"`
	Features                      uint64              `plist:"features"`
	FeaturesEx                    FeatureSet          `plist:"featuresEx"`
	StatusFlags                   uint64              `plist:"statusFlags"`
	PK                            plistData           `plist:"pk"`
	TXTAirPlay                    []byte              `plist:"txtAirPlay"`
	SupportedFormats              StreamFormats       `plist:"supportedFormats"`
	SupportedAudioFormatsExtended map[string][]uint64 `plist:"supportedAudioFormatsExtended"`
	HasUDPMirror                  bool                `plist:"hasUDPMirroringSupport"`
	HDRCapability                 string              `plist:"receiverHDRCapability"`
	VolumeControlType             int                 `plist:"volumeControlType"`
	InitialVolume                 float64             `plist:"initialVolume"`
	KeepAliveBody                 plistFlag           `plist:"keepAliveSendStatsAsBody"`
	PSI                           string              `plist:"psi"`
	PI                            string              `plist:"pi"`
	MacAddress                    string              `plist:"macAddress"`
	Displays                      []DisplayInfo       `plist:"displays"`
	hasPTPInfo                    bool
}

// FormatMask preserves the unsigned bit pattern of signed or unsigned plist
// integers. Some Apple receivers encode bufferStream with bit 63 set, which
// appears as a negative integer in the plist.
type FormatMask uint64

func (m *FormatMask) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var signed int64
	if err := unmarshal(&signed); err == nil {
		*m = FormatMask(uint64(signed))
		return nil
	}
	var unsigned uint64
	if err := unmarshal(&unsigned); err != nil {
		return err
	}
	*m = FormatMask(unsigned)
	return nil
}

// StreamFormats contains the audio format masks from /info supportedFormats.
type StreamFormats struct {
	AudioStream           FormatMask `plist:"audioStream"`
	BufferStream          FormatMask `plist:"bufferStream"`
	LowLatencyAudioStream FormatMask `plist:"lowLatencyAudioStream"`
	ScreenStream          FormatMask `plist:"screenStream"`
}

// SupportsAudioFormat reports whether every requested format bit is advertised
// for the named supportedFormats stream.
func (i *ReceiverInfo) SupportsAudioFormat(stream string, mask uint64) bool {
	if i == nil || mask == 0 {
		return false
	}
	var advertised FormatMask
	switch stream {
	case "audioStream":
		advertised = i.SupportedFormats.AudioStream
	case "bufferStream":
		advertised = i.SupportedFormats.BufferStream
	case "lowLatencyAudioStream":
		advertised = i.SupportedFormats.LowLatencyAudioStream
	case "screenStream":
		advertised = i.SupportedFormats.ScreenStream
	default:
		return false
	}
	return uint64(advertised)&mask == mask
}

// AirPlay receiver status flags used to choose one authentication prompt.
// Apple's receiver publishes a configured playback password as bit 7 and
// one-time on-screen PIN pairing as bit 9. Password takes precedence when both
// are present, matching the sender framework's AirPlay security selection.
const (
	statusFlagPasswordRequired      uint64 = 1 << 7
	statusFlagPINRequiredForPairing uint64 = 1 << 9
)

// PairingCredential describes the value, if any, that belongs in full SRP
// pair-setup. A receiver's fixed playback password is normally only an HTTP
// Digest credential; legacy receivers are the exception and also use it for
// pair-setup.
type PairingCredential uint8

const (
	PairingCredentialNone PairingCredential = iota
	PairingCredentialPIN
	PairingCredentialPassword
)

// RequiresPassword reports whether the receiver has a configured password.
// The value should be requested once and retained for Digest authentication;
// legacy pairing implementations may also use it for SRP pair-setup.
func (i *ReceiverInfo) RequiresPassword() bool {
	return i != nil && i.StatusFlags&statusFlagPasswordRequired != 0
}

// RequiresPINPairing reports whether the receiver requires one-time pairing
// with an onscreen code. This is distinct from the receiver's per-session PIN
// and fixed-password status bits. The pairing implementation chooses the
// receiver's modern or legacy wire format separately.
func (i *ReceiverInfo) RequiresPINPairing() bool {
	return i != nil && i.StatusFlags&statusFlagPINRequiredForPairing != 0
}

// RequiredPairingCredential resolves the receiver's password and PIN flags
// against its pairing generation. Some modern receivers advertise both: the
// fixed password takes precedence for the user-facing prompt, but is retained
// exclusively for Digest while transient HAP pairing proceeds without a code.
func (i *ReceiverInfo) RequiredPairingCredential() PairingCredential {
	if i == nil {
		return PairingCredentialNone
	}
	if i.RequiresPassword() {
		if i.PrefersLegacyPairing() {
			return PairingCredentialPassword
		}
		return PairingCredentialNone
	}
	if i.RequiresPINPairing() {
		return PairingCredentialPIN
	}
	return PairingCredentialNone
}

// DisplayInfo describes a receiver display advertised in the /info response.
type DisplayInfo struct {
	Width           plistNumber `plist:"width"`
	Height          plistNumber `plist:"height"`
	WidthPixels     plistNumber `plist:"widthPixels"`
	HeightPixels    plistNumber `plist:"heightPixels"`
	WidthPixelsMax  plistNumber `plist:"widthPixelsMax"`
	HeightPixelsMax plistNumber `plist:"heightPixelsMax"`
}

// DisplaySize returns the receiver's primary display resolution in pixels, or
// (0, 0) if the receiver did not advertise a usable display size.
func (i *ReceiverInfo) DisplaySize() (int, int) {
	if i == nil || len(i.Displays) == 0 {
		return 0, 0
	}
	d := i.Displays[0]
	w, h := d.WidthPixels, d.HeightPixels
	if w <= 0 || h <= 0 {
		w, h = d.Width, d.Height
	}
	if w <= 0 || h <= 0 {
		return 0, 0
	}
	return int(w), int(h)
}

// MirrorSize returns the receiver's nominal screen-mirroring canvas. This is
// deliberately distinct from MaxVideoSize: current receivers can advertise a
// 1920x1080 canvas and a 3840x2160 maximum, and Apple's ordinary screen path
// uses the nominal dimensions unless its separate high-resolution path is
// selected.
//
// Before a media session exists, some receivers omit displays entirely. In
// that provisional state Apple's endpoint default is selected by feature 28.
func (i *ReceiverInfo) MirrorSize() (int, int) {
	if i == nil {
		return 0, 0
	}
	if w, h := i.DisplaySize(); w > 0 && h > 0 {
		return w, h
	}
	if i.HasFeature(7) {
		if i.HasFeature(28) {
			return 1920, 1080
		}
		return 1280, 720
	}
	return 0, 0
}

// MaxVideoSize returns the largest encoded frame the receiver says its decoder
// accepts. Receivers that omit explicit maxima fall back to their display size.
//
// Screen receivers often omit display metadata entirely. Apple's sender uses
// endpoint feature 28 to choose a 1920x1080 default; otherwise it uses the
// legacy 1280x720 default.
func (i *ReceiverInfo) MaxVideoSize() (int, int) {
	if i == nil {
		return 0, 0
	}
	if len(i.Displays) > 0 {
		d := i.Displays[0]
		if d.WidthPixelsMax > 0 && d.HeightPixelsMax > 0 {
			return int(d.WidthPixelsMax), int(d.HeightPixelsMax)
		}
	}
	return i.MirrorSize()
}

// HTTPStatusError is returned when a receiver responds with a non-2xx RTSP/HTTP status.
type HTTPStatusError struct {
	StatusCode int
	Body       []byte
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP %d (body: %s)", e.StatusCode, string(e.Body))
}

// ErrCredentialsRequired identifies a Digest challenge that the client cannot
// answer because no receiver code/password has been configured. Callers may
// obtain the credential, call SetPassword, and retry the failed operation on
// the same connection. The concrete error also unwraps the original
// HTTPStatusError.
var ErrCredentialsRequired = errors.New("receiver credentials required")

// CredentialsRequiredError describes the Digest realm which requested a
// receiver code/password. Use errors.Is(err, ErrCredentialsRequired) when the
// realm itself is not needed.
type CredentialsRequiredError struct {
	Realm string
	err   error
}

func (e *CredentialsRequiredError) Error() string {
	return fmt.Sprintf("receiver requires a code or password for Digest realm %q: %v", e.Realm, e.err)
}

func (e *CredentialsRequiredError) Unwrap() error { return e.err }

func (e *CredentialsRequiredError) Is(target error) bool {
	return target == ErrCredentialsRequired
}

// AirPlayClient manages the connection to an AirPlay receiver.
type AirPlayClient struct {
	host string
	port int
	// advertisement is the optional mDNS snapshot used only to fill fields
	// omitted by /info. Explicit /info values always take precedence.
	advertisement *AirPlayDevice

	conn      net.Conn
	mu        sync.Mutex
	cseq      atomic.Int64
	info      *ReceiverInfo
	PairKeys  *PairKeys
	sessionID string // X-Apple-Session-ID, set once per connection
	PairingID string // Our pairing identifier (UUID)
	pairType  int    // X-Apple-HKP pairing type for the current exchange
	// pairingProtocol records the wire protocol that actually completed on this
	// connection. It starts unset because feature flags choose only which
	// protocol to probe first; a receiver may advertise HAP while implementing
	// only the original raw AirPlay exchange.
	pairingProtocol pairingProtocol

	// Encryption state after pair-verify
	encrypted     bool
	encWriteKey   []byte
	encReadKey    []byte
	encWriteNonce uint64
	encReadNonce  uint64
	encCipher     cipher.AEAD

	// FairPlay derived key for stream encryption
	fpKey    []byte
	fpIV     []byte
	FpEkey   []byte // 72-byte wrapped key for SETUP
	fpM3     []byte // 164-byte FPLY-wrapped m3 (needed for ekey construction)
	fpAesKey []byte // 16-byte raw aesKey from FairPlay key unwrap (IKM for HKDF)

	// Stream encryption key (from FP or pair-verify)
	streamKey []byte
	streamIV  []byte

	// HTTP Digest credentials, used only when the receiver has "Require
	// Password" enabled and challenges a request with 401. Pair-setup and
	// Digest are separate protocols, but a non-empty Pair code is retained here
	// because receivers may use the same user-facing value for both.
	authPassword string
	// Most recent Digest challenge seen on this connection. Cached so later
	// requests can authenticate up front instead of relying on a retry.
	authChallenge *digestChallenge
}

func NewAirPlayClient(host string, port int) *AirPlayClient {
	return &AirPlayClient{
		host:      host,
		port:      port,
		sessionID: generateUUID(),
		PairingID: generateUUID(),
		pairType:  pairingTypeScreenCapture,
	}
}

// NewAirPlayClientForDevice creates a client seeded with the complete mDNS
// advertisement. GetInfo uses it only for values omitted by the receiver.
func NewAirPlayClientForDevice(device AirPlayDevice) *AirPlayClient {
	client := NewAirPlayClient(device.IP, device.Port)
	client.SetAdvertisement(device)
	return client
}

// SetAdvertisement seeds the mDNS capability snapshot used by GetInfo.
func (c *AirPlayClient) SetAdvertisement(device AirPlayDevice) {
	copy := cloneAirPlayDevice(device)
	c.mu.Lock()
	c.advertisement = &copy
	c.mu.Unlock()
}

func cloneAirPlayDevice(device AirPlayDevice) AirPlayDevice {
	device.FeaturesEx = device.FeaturesEx.clone()
	device.RawTXT = cloneTXT(device.RawTXT)
	return device
}

// SetPassword configures the password used to answer HTTP Digest challenges
// from receivers with "Require Password" enabled. An empty password leaves
// authentication disabled; a valid Digest challenge then surfaces as
// ErrCredentialsRequired. Pair also calls this automatically when given a
// non-empty PIN/password.
func (c *AirPlayClient) SetPassword(password string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authPassword = password
}

// digestRetryHeader returns an Authorization header value when err is a 401
// carrying a Digest challenge we hold credentials for. When no credential is
// configured, it replaces the opaque 401 with ErrCredentialsRequired while
// preserving that HTTPStatusError in the unwrap chain. Callers retry at most
// once: if the authenticated request is rejected too, that error surfaces
// rather than looping.
//
// Must be called with c.mu held.
func (c *AirPlayClient) digestRetryHeader(method, uri string, respHeaders map[string]string, err error) (string, bool, error) {
	if err == nil {
		return "", false, nil
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != 401 {
		return "", false, err
	}

	// Indexing a nil map is fine; a 401 without the header just means we
	// cannot answer it.
	ch, ok := parseDigestChallenge(respHeaders["www-authenticate"])
	if !ok {
		log.Printf("warning: %s %s was rejected with 401 but sent no Digest challenge to answer", method, uri)
		return "", false, err
	}
	// Cache it even when we cannot answer right now, so the rest of the session
	// authenticates up front: a receiver that challenges one request challenges
	// them all, and a mirroring session issues around two dozen.
	c.authChallenge = ch

	if c.authPassword == "" {
		return "", false, &CredentialsRequiredError{Realm: ch.Realm, err: err}
	}

	return authorizationHeader(DigestUsername, c.authPassword, ch, method, uri), true, err
}

// preemptiveAuthHeader returns an Authorization header built from the cached
// challenge, so a request that already knows it will be challenged answers up
// front rather than being sent twice.
//
// Must be called with c.mu held.
func (c *AirPlayClient) preemptiveAuthHeader(method, uri string) (string, bool) {
	if c.authPassword == "" || c.authChallenge == nil {
		return "", false
	}
	return authorizationHeader(DigestUsername, c.authPassword, c.authChallenge, method, uri), true
}

// logIfAuthRejected reports a second 401 distinctly from the first. Reaching
// here means a password was sent and refused -- a different problem from
// having none at all.
func (c *AirPlayClient) logIfAuthRejected(method, uri string, err error) {
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == 401 {
		log.Printf("%s %s: receiver rejected the code (Digest username %q)", method, uri, DigestUsername)
	}
}

// withHeader returns a copy of hdrs with key set. Call sites reuse their header
// maps across requests, so mutating the original would leak a stale nonce into
// later ones.
func withHeader(hdrs map[string]string, key, value string) map[string]string {
	out := make(map[string]string, len(hdrs)+1)
	for k, v := range hdrs {
		out[k] = v
	}
	out[key] = value
	return out
}

func (c *AirPlayClient) Connect(ctx context.Context) error {
	addr := net.JoinHostPort(c.host, fmt.Sprintf("%d", c.port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	c.conn = conn
	return nil
}

func (c *AirPlayClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ClearSessionID clears the session ID so requests don't include X-Apple-Session-ID.
// Used for the raw/legacy protocol path (raw pair-verify).
func (c *AirPlayClient) ClearSessionID() {
	c.sessionID = ""
}

func (c *AirPlayClient) GetInfo() (*ReceiverInfo, error) {
	return c.getInfoWithTimeout(0)
}

func (c *AirPlayClient) getInfoWithTimeout(timeout time.Duration) (*ReceiverInfo, error) {
	resp, responseHeaders, err := c.httpRequestWithHeadersTimeout("GET", "/info", "application/x-apple-binary-plist", nil, timeout)
	if err != nil {
		return nil, err
	}

	// Log the full /info response for debugging audio format support
	var fullInfo map[string]interface{}
	if _, err2 := plist.Unmarshal(resp, &fullInfo); err2 == nil {
		dbg("[INFO] full /info response keys: %v", func() []string {
			keys := make([]string, 0, len(fullInfo))
			for k := range fullInfo {
				keys = append(keys, k)
			}
			return keys
		}())
		for _, key := range []string{"audioFormats", "audioLatencies", "displays", "features", "featuresEx", "statusFlags", "initialVolume", "volumeControlType", "keepAliveSendStatsAsBody", "supportedAudioFormatsExtended", "supportedFormats", "PTPInfo"} {
			if v, ok := fullInfo[key]; ok {
				dbg("[INFO] %s: %+v", key, v)
			}
		}
	}

	var info ReceiverInfo
	if _, err := plist.Unmarshal(resp, &info); err != nil {
		return nil, fmt.Errorf("decode info plist: %w", err)
	}
	info.Server = responseHeaders["server"]
	_, info.hasPTPInfo = fullInfo["PTPInfo"]

	c.mu.Lock()
	var advertisement *AirPlayDevice
	if c.advertisement != nil {
		copy := cloneAirPlayDevice(*c.advertisement)
		advertisement = &copy
	}
	c.mu.Unlock()
	mergeAdvertisementIntoReceiverInfo(&info, fullInfo, advertisement)
	c.info = &info
	return &info, nil
}

// applyReceiverInfoUpdate merges a partial receiver-info dictionary into the
// current capability snapshot. Control SETUP can return this dictionary under
// its "info" key after the receiver has created the media session; at that
// point displays may be present even though the initial GET /info omitted them.
//
// Decode into a copy so keys omitted by a qualified response retain their
// earlier values. The update itself has higher precedence than the initial
// response and mDNS snapshot.
func (c *AirPlayClient) applyReceiverInfoUpdate(update map[string]interface{}, server string) (*ReceiverInfo, error) {
	if update == nil {
		return c.info, nil
	}
	body, err := plist.Marshal(update, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("encode receiver info update: %w", err)
	}
	var info ReceiverInfo
	if c.info != nil {
		info = *c.info
		info.FeaturesEx = c.info.FeaturesEx.clone()
		info.PK = append(plistData(nil), c.info.PK...)
		info.TXTAirPlay = append([]byte(nil), c.info.TXTAirPlay...)
		info.Displays = append([]DisplayInfo(nil), c.info.Displays...)
		info.SupportedAudioFormatsExtended = cloneAudioFormats(c.info.SupportedAudioFormatsExtended)
	}
	// howett/plist appends slices and merges maps when decoding into a populated
	// value. Session-time values are replacements, not additions: in particular,
	// retaining the provisional display ahead of the authenticated display would
	// keep MirrorSize pinned to the old 720p entry. Clear explicitly present
	// aggregate fields before decoding while leaving omitted fields untouched.
	if _, ok := update["featuresEx"]; ok {
		info.FeaturesEx = nil
	}
	if _, ok := update["pk"]; ok {
		info.PK = nil
	}
	if _, ok := update["txtAirPlay"]; ok {
		info.TXTAirPlay = nil
	}
	if _, ok := update["supportedFormats"]; ok {
		info.SupportedFormats = StreamFormats{}
	}
	if _, ok := update["supportedAudioFormatsExtended"]; ok {
		info.SupportedAudioFormatsExtended = nil
	}
	if _, ok := update["displays"]; ok {
		info.Displays = nil
	}
	if _, err := plist.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("decode receiver info update: %w", err)
	}
	if server != "" {
		info.Server = server
	}
	if _, ok := update["PTPInfo"]; ok {
		info.hasPTPInfo = true
	}
	c.info = &info
	return &info, nil
}

func cloneAudioFormats(source map[string][]uint64) map[string][]uint64 {
	if source == nil {
		return nil
	}
	clone := make(map[string][]uint64, len(source))
	for stream, formats := range source {
		clone[stream] = append([]uint64(nil), formats...)
	}
	return clone
}

func mergeAdvertisementIntoReceiverInfo(info *ReceiverInfo, fullInfo map[string]interface{}, mdns *AirPlayDevice) {
	if info == nil {
		return
	}
	present := make(map[string]bool, len(fullInfo)+10)
	for key := range fullInfo {
		present[key] = true
	}
	// When /info omits the legacy integer but supplies its complete extended
	// representation, derive the low prefix before considering lower-precedence
	// embedded or mDNS advertisements.
	if !present["features"] && present["featuresEx"] && len(info.FeaturesEx) > 0 {
		info.Features = info.FeaturesEx.Low64()
		present["features"] = true
	}

	// Current Apple receivers repeat mDNS as DNS TXT wire data inside /info.
	// It is newer than the discovery snapshot but remains subordinate to
	// explicit top-level /info fields.
	if len(info.TXTAirPlay) > 0 {
		embedded := &AirPlayDevice{}
		populateDeviceFromTXT(embedded, parseTXTWire(info.TXTAirPlay))
		mergeAdvertisementFields(info, present, embedded)
	}
	mergeAdvertisementFields(info, present, mdns)

	// featuresEx contains the complete legacy prefix on current receivers. If
	// the numeric legacy field was omitted, recover it from that prefix.
	if !present["features"] && len(info.FeaturesEx) > 0 {
		info.Features = info.FeaturesEx.Low64()
		present["features"] = true
	}
	if !present["sourceVersion"] {
		if version, ok := airTunesServerVersion(info.Server); ok {
			info.SourceVersion = version
			present["sourceVersion"] = true
		}
	}
}

func airTunesServerVersion(server string) (string, bool) {
	name, version, ok := strings.Cut(strings.TrimSpace(server), "/")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), "AirTunes") {
		return "", false
	}
	version = strings.TrimSpace(version)
	return version, version != ""
}

func mergeAdvertisementFields(info *ReceiverInfo, present map[string]bool, source *AirPlayDevice) {
	if source == nil {
		return
	}
	hasTXT := func(key string) bool {
		_, ok := source.RawTXT[key]
		return ok
	}
	fillString := func(infoKey, txtKey string, destination *string, value string) {
		if !present[infoKey] && (value != "" || hasTXT(txtKey)) {
			*destination = value
			present[infoKey] = true
		}
	}

	fillString("name", "name", &info.Name, source.Name)
	fillString("model", "model", &info.Model, source.Model)
	fillString("deviceID", "deviceid", &info.DeviceID, source.DeviceID)
	fillString("protocolVersion", "protovers", &info.ProtocolVersion, source.ProtocolVersion)
	fillString("sourceVersion", "srcvers", &info.SourceVersion, source.SourceVersion)
	fillString("pi", "pi", &info.PI, source.PI)
	fillString("psi", "psi", &info.PSI, source.PSI)

	if !present["vv"] && (source.VV != 0 || hasTXT("vv")) {
		info.VV = source.VV
		present["vv"] = true
	}
	if !present["features"] && (source.Features != 0 || hasTXT("features") || hasTXT("fex")) {
		info.Features = source.Features
		present["features"] = true
	}
	if !present["featuresEx"] && (len(source.FeaturesEx) > 0 || hasTXT("fex")) {
		info.FeaturesEx = source.FeaturesEx.clone()
		present["featuresEx"] = true
	}
	if !present["statusFlags"] && (source.Flags != 0 || hasTXT("flags")) {
		info.StatusFlags = source.Flags
		present["statusFlags"] = true
	}
	if !present["pk"] && (source.PK != "" || hasTXT("pk")) {
		if publicKey, err := hex.DecodeString(strings.TrimSpace(source.PK)); err == nil {
			info.PK = plistData(publicKey)
			present["pk"] = true
		}
	}
}

func parseTXTWire(data []byte) map[string]string {
	records := make([]string, 0, 16)
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		offset++
		if length > len(data)-offset {
			break
		}
		records = append(records, string(data[offset:offset+length]))
		offset += length
	}
	return parseTXT(records)
}

func (c *AirPlayClient) Pair(ctx context.Context, pin string) error {
	if pin != "" {
		c.SetPassword(pin)
		// Current receivers use a configured playback password for HTTP Digest,
		// not SRP. Keep the caller's single credential for Digest while probing
		// transient pairing with the empty HAP secret. Legacy receivers advertise
		// that their password belongs in full pair-setup instead.
		if c.info != nil && c.info.RequiresPassword() &&
			c.info.RequiredPairingCredential() == PairingCredentialNone {
			return c.pairTransient(ctx)
		}
		return c.pairWithPIN(ctx, pin)
	}
	return c.pairTransient(ctx)
}

func (c *AirPlayClient) SetupMirror(ctx context.Context, cfg StreamConfig) (*MirrorSession, error) {
	if cfg.VideoCodec == VideoCodecAuto {
		return nil, fmt.Errorf("automatic video codec requires SetupMirrorWithVideoCodecPreparation")
	}
	return c.setupMirrorSession(ctx, cfg, nil, false)
}

// SetupMirrorWithVideoPreparation is SetupMirror with a hook at the protocol
// boundary where session-time display information is available but media
// streams have not yet been configured. The hook should only launch an already
// authorized capture source; interactive portal work belongs before this call.
func (c *AirPlayClient) SetupMirrorWithVideoPreparation(ctx context.Context, cfg StreamConfig, prepare func(width, height int) error) (*MirrorSession, error) {
	if cfg.VideoCodec == VideoCodecAuto {
		return nil, fmt.Errorf("automatic video codec requires SetupMirrorWithVideoCodecPreparation")
	}
	if prepare == nil {
		return c.setupMirrorSession(ctx, cfg, nil, false)
	}
	return c.setupMirrorSession(ctx, cfg, func(width, height int, _ VideoCodec) (VideoPreparationResult, error) {
		return VideoPreparationResult{}, prepare(width, height)
	}, false)
}

// VideoPreparationResult reports information which is only knowable after the
// concrete receiver canvas and codec have launched the real capture pipeline.
// MinimumVideoLead is a lower bound; it never reduces an earlier preflight
// measurement or an explicit user-selected target.
type VideoPreparationResult struct {
	MinimumVideoLead time.Duration
}

// SetupMirrorWithVideoCodecPreparation is the automatic-codec variant of
// SetupMirrorWithVideoPreparation. Its hook receives the concrete codec chosen
// from final session-time receiver information, so capture and wire framing use
// the same format.
func (c *AirPlayClient) SetupMirrorWithVideoCodecPreparation(ctx context.Context, cfg StreamConfig, prepare func(width, height int, codec VideoCodec) error) (*MirrorSession, error) {
	if prepare == nil {
		return c.setupMirrorSession(ctx, cfg, nil, false)
	}
	return c.setupMirrorSession(ctx, cfg, func(width, height int, codec VideoCodec) (VideoPreparationResult, error) {
		return VideoPreparationResult{}, prepare(width, height, codec)
	}, false)
}

// SetupMirrorWithCalibratedVideoPreparation is the result-bearing variant of
// SetupMirrorWithVideoCodecPreparation. The hook runs before audio and video
// SETUP commit their latency descriptors, allowing a timestamped production
// capture to report its measured minimum video lead without a clock mismatch.
func (c *AirPlayClient) SetupMirrorWithCalibratedVideoPreparation(ctx context.Context, cfg StreamConfig, prepare func(width, height int, codec VideoCodec) (VideoPreparationResult, error)) (*MirrorSession, error) {
	return c.setupMirrorSession(ctx, cfg, prepare, prepare != nil)
}

// httpRequest sends an RTSP/1.0 request over the AirPlay connection and returns the response body.
// Used for /info, /pair-setup, /pair-verify, /fp-setup etc. (RAOP connection type).
// Does NOT send X-Apple-Session-ID: legacy CSeq/RAOP handlers can reject or
// crash on the combination, while the TCP connection already identifies it.
func (c *AirPlayClient) httpRequest(method, path, contentType string, body []byte, extraHeaders ...map[string]string) ([]byte, error) {
	respBody, _, err := c.httpRequestWithHeaders(method, path, contentType, body, extraHeaders...)
	return respBody, err
}

func (c *AirPlayClient) httpRequestWithHeaders(method, path, contentType string, body []byte, extraHeaders ...map[string]string) ([]byte, map[string]string, error) {
	return c.httpRequestWithHeadersTimeout(method, path, contentType, body, 0, extraHeaders...)
}

func (c *AirPlayClient) httpRequestWithHeadersTimeout(method, path, contentType string, body []byte, timeout time.Duration, extraHeaders ...map[string]string) ([]byte, map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if authHdr, ok := c.preemptiveAuthHeader(method, path); ok {
		dbg("[HTTP] authenticating %s %s up front from the cached challenge", method, path)
		extraHeaders = append(append([]map[string]string{}, extraHeaders...), map[string]string{"Authorization": authHdr})
	}

	respBody, respHeaders, err := c.httpRequestOnce(method, path, contentType, body, timeout, extraHeaders...)
	var authHdr string
	var retry bool
	authHdr, retry, err = c.digestRetryHeader(method, path, respHeaders, err)
	if retry {
		dbg("[HTTP] 401 digest challenge on %s %s, retrying with credentials", method, path)
		retry := append(append([]map[string]string{}, extraHeaders...), map[string]string{"Authorization": authHdr})
		respBody, respHeaders, err = c.httpRequestOnce(method, path, contentType, body, timeout, retry...)
		c.logIfAuthRejected(method, path, err)
	}
	return respBody, respHeaders, err
}

func (c *AirPlayClient) httpRequestOnce(method, path, contentType string, body []byte, timeout time.Duration, extraHeaders ...map[string]string) ([]byte, map[string]string, error) {
	seq := c.cseq.Add(1)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s RTSP/1.0\r\n", method, path)
	fmt.Fprintf(&buf, "CSeq: %d\r\n", seq)
	fmt.Fprintf(&buf, "User-Agent: AirPlay/935.7.1\r\n")
	for _, hdrs := range extraHeaders {
		for k, v := range hdrs {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	if contentType != "" && len(body) > 0 {
		fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	buf.WriteString("\r\n")
	buf.Write(body)

	data := buf.Bytes()

	dbg("[HTTP] -> %s %s (body=%d bytes, encrypted=%v, cseq=%d)", method, path, len(body), c.encrypted, seq)
	if c.encrypted {
		plainLen := len(data)
		data = c.encrypt(data)
		dbg("[HTTP] encrypted %d plaintext -> %d ciphertext bytes", plainLen, len(data))
	}

	if _, err := c.conn.Write(data); err != nil {
		return nil, nil, fmt.Errorf("write request: %w", err)
	}
	dbg("[HTTP] wrote %d bytes to socket, waiting for response...", len(data))

	return c.readHTTPResponseWithTimeout(timeout)
}

// rawRequest sends a bare RTSP/1.0 request without X-Apple-Session-ID or HAP
// encryption. Used for the raw binary pair-verify protocol.
func (c *AirPlayClient) rawRequest(method, path, contentType string, body []byte, extraHeaders ...map[string]string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seq := c.cseq.Add(1)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s RTSP/1.0\r\n", method, path)
	fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&buf, "User-Agent: AirPlay/935.7.1\r\n")
	fmt.Fprintf(&buf, "X-Apple-ProtocolVersion: 1\r\n")
	for _, hdrs := range extraHeaders {
		for k, v := range hdrs {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&buf, "CSeq: %d\r\n", seq)
	buf.WriteString("\r\n")
	buf.Write(body)

	data := buf.Bytes()
	dbg("[RAW] -> %s %s (body=%d bytes, cseq=%d)", method, path, len(body), seq)

	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	resp, _, err := c.readHTTPResponse()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// rtspRequest sends an RTSP/1.0 request (used after pairing for mirror setup).
func (c *AirPlayClient) rtspRequest(method, uri, contentType string, body []byte, extraHeaders map[string]string) ([]byte, map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if authHdr, ok := c.preemptiveAuthHeader(method, uri); ok {
		dbg("[RTSP] authenticating %s %s up front from the cached challenge", method, uri)
		extraHeaders = withHeader(extraHeaders, "Authorization", authHdr)
	}

	respBody, respHeaders, err := c.rtspRequestOnce(method, uri, contentType, body, extraHeaders)
	var authHdr string
	var retry bool
	authHdr, retry, err = c.digestRetryHeader(method, uri, respHeaders, err)
	if retry {
		dbg("[RTSP] 401 digest challenge on %s %s, retrying with credentials", method, uri)
		respBody, respHeaders, err = c.rtspRequestOnce(method, uri, contentType, body, withHeader(extraHeaders, "Authorization", authHdr))
		c.logIfAuthRejected(method, uri, err)
	}
	return respBody, respHeaders, err
}

func (c *AirPlayClient) rtspRequestOnce(method, uri, contentType string, body []byte, extraHeaders map[string]string) ([]byte, map[string]string, error) {
	seq := c.cseq.Add(1)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s RTSP/1.0\r\n", method, uri)
	fmt.Fprintf(&buf, "CSeq: %d\r\n", seq)
	fmt.Fprintf(&buf, "User-Agent: AirPlay/935.7.1\r\n")
	// Do not send X-Apple-Session-ID here. Legacy CSeq/RAOP handlers can reject
	// the combination, and the session is already identified by the TCP connection.
	for k, v := range extraHeaders {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	if contentType != "" && len(body) > 0 {
		fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	buf.WriteString("\r\n")
	buf.Write(body)

	data := buf.Bytes()
	dbg("[RTSP] -> %s %s (body=%d bytes, encrypted=%v, cseq=%d)", method, uri, len(body), c.encrypted, seq)
	if c.encrypted {
		plainLen := len(data)
		data = c.encrypt(data)
		dbg("[RTSP] encrypted %d plaintext -> %d ciphertext bytes", plainLen, len(data))
	}

	if _, err := c.conn.Write(data); err != nil {
		return nil, nil, fmt.Errorf("write request: %w", err)
	}
	dbg("[RTSP] wrote %d bytes to socket, waiting for response...", len(data))

	respBody, respHeaders, err := c.readHTTPResponse()
	if err != nil {
		// Return the headers even on failure: a 401 carries its
		// WWW-Authenticate challenge there, and dropping them makes an
		// answerable challenge look like an unanswerable one.
		return nil, respHeaders, err
	}

	dbg("[RTSP] <- response body %d bytes", len(respBody))
	return respBody, respHeaders, nil
}

func (c *AirPlayClient) readHTTPResponse() ([]byte, map[string]string, error) {
	return c.readHTTPResponseWithTimeout(0)
}

func (c *AirPlayClient) readHTTPResponseWithTimeout(timeout time.Duration) ([]byte, map[string]string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer c.conn.SetReadDeadline(time.Time{})

	if c.encrypted {
		dbg("[READ] reading encrypted response (readKey=%s, readNonce=%d)", hex.EncodeToString(c.encReadKey[:8]), c.encReadNonce)
		return c.readEncryptedHTTPResponse()
	}
	dbg("[READ] reading plaintext response")
	return c.readPlaintextHTTPResponse()
}

func (c *AirPlayClient) readPlaintextHTTPResponse() ([]byte, map[string]string, error) {
	// Read headers byte-by-byte until \r\n\r\n
	var headerBuf bytes.Buffer
	oneByte := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c.conn, oneByte); err != nil {
			return nil, nil, fmt.Errorf("read response header (got %d bytes so far: %q): %w", headerBuf.Len(), headerBuf.String(), err)
		}
		headerBuf.Write(oneByte)

		b := headerBuf.Bytes()
		if len(b) >= 4 && bytes.Equal(b[len(b)-4:], []byte("\r\n\r\n")) {
			break
		}
		if headerBuf.Len() > 16384 {
			return nil, nil, fmt.Errorf("response header too large")
		}
	}

	header := headerBuf.String()
	dbg("[READ] plaintext response header:\n%s", header)
	statusCode, contentLength, headers := parseHTTPHeader(header)
	dbg("[READ] status=%d content-length=%d", statusCode, contentLength)
	if err := validateContentLength(contentLength); err != nil {
		return nil, headers, err
	}

	if statusCode < 200 || statusCode >= 300 {
		// Drain the complete body so the next request begins on an RTSP response
		// boundary. A partial error body is a transport failure, not a usable HTTP
		// status: returning HTTPStatusError would let callers continue on a poisoned
		// sequential connection.
		var errBody []byte
		if contentLength > 0 {
			errBody = make([]byte, contentLength)
			if _, err := io.ReadFull(c.conn, errBody); err != nil {
				return nil, headers, fmt.Errorf("read error response body (%d bytes): %w", contentLength, err)
			}
		}
		dbg("[READ] error response body (%d bytes): %s", len(errBody), hex.EncodeToString(errBody))
		return nil, headers, &HTTPStatusError{StatusCode: statusCode, Body: errBody}
	}

	if contentLength == 0 {
		return nil, headers, nil
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return nil, headers, fmt.Errorf("read body (%d/%d bytes): %w", 0, contentLength, err)
	}

	dbg("[READ] plaintext body: %d bytes", len(body))
	return body, headers, nil
}

func (c *AirPlayClient) readEncryptedHTTPResponse() ([]byte, map[string]string, error) {
	// Read and decrypt frames, then parse the HTTP response from decrypted data.
	// We accumulate decrypted data until we have the full response.
	var decrypted []byte
	frameCount := 0

	// Read frames until we have the HTTP headers
	dbg("[ENC-READ] starting to read encrypted frames...")
	for {
		frame, err := c.readEncryptedFrame()
		if err != nil {
			dbg("[ENC-READ] frame %d read error (decrypted so far=%d bytes): %v", frameCount, len(decrypted), err)
			if len(decrypted) > 0 {
				dbg("[ENC-READ] partial decrypted data hex: %s", hex.EncodeToString(decrypted))
			}
			return nil, nil, fmt.Errorf("read encrypted response frame %d: %w", frameCount, err)
		}
		frameCount++
		dbg("[ENC-READ] frame %d: %d bytes decrypted", frameCount, len(frame))
		decrypted = append(decrypted, frame...)

		// Check if we have the full headers
		if idx := bytes.Index(decrypted, []byte("\r\n\r\n")); idx >= 0 {
			dbg("[ENC-READ] found header end after %d frames, %d total bytes", frameCount, len(decrypted))
			break
		}
		if len(decrypted) > 16384 {
			return nil, nil, fmt.Errorf("encrypted response header too large")
		}
	}

	headerEnd := bytes.Index(decrypted, []byte("\r\n\r\n"))
	header := string(decrypted[:headerEnd+4])
	remaining := decrypted[headerEnd+4:]

	dbg("[ENC-READ] decrypted response header:\n%s", header)
	statusCode, contentLength, headers := parseHTTPHeader(header)
	dbg("[ENC-READ] status=%d content-length=%d remaining=%d", statusCode, contentLength, len(remaining))
	if err := validateContentLength(contentLength); err != nil {
		return nil, headers, err
	}

	if statusCode < 200 || statusCode >= 300 {
		// Consume the entire encrypted error response before returning a semantic
		// status. Otherwise a caller could mistake the remainder for the next
		// response frame on this nonce-ordered connection.
		for len(remaining) < contentLength && contentLength > 0 {
			frame, err := c.readEncryptedFrame()
			if err != nil {
				return nil, headers, fmt.Errorf("read encrypted error body (%d/%d bytes): %w", len(remaining), contentLength, err)
			}
			remaining = append(remaining, frame...)
		}
		if len(remaining) > contentLength && contentLength > 0 {
			remaining = remaining[:contentLength]
		}
		dbg("[ENC-READ] error response body (%d bytes): %s", len(remaining), hex.EncodeToString(remaining))
		return nil, headers, &HTTPStatusError{StatusCode: statusCode, Body: remaining}
	}

	if contentLength == 0 {
		return nil, headers, nil
	}

	// Read more frames if we don't have the full body yet
	for len(remaining) < contentLength {
		frame, err := c.readEncryptedFrame()
		if err != nil {
			dbg("[ENC-READ] body frame error (have %d/%d bytes): %v", len(remaining), contentLength, err)
			return nil, headers, fmt.Errorf("read encrypted body (%d/%d bytes): %w", len(remaining), contentLength, err)
		}
		remaining = append(remaining, frame...)
	}

	dbg("[ENC-READ] complete: %d body bytes in %d+ frames", contentLength, frameCount)
	return remaining[:contentLength], headers, nil
}

func parseHTTPHeader(header string) (statusCode, contentLength int, headers map[string]string) {
	headers = make(map[string]string)
	fmt.Sscanf(header, "HTTP/1.1 %d", &statusCode)
	if statusCode == 0 {
		fmt.Sscanf(header, "RTSP/1.0 %d", &statusCode)
	}

	for _, line := range strings.Split(header, "\r\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		headers[key] = value
		if key == "content-length" {
			fmt.Sscanf(value, "%d", &contentLength)
		}
	}
	return
}

func (c *AirPlayClient) encrypt(data []byte) []byte {
	if !c.encrypted || c.encCipher == nil {
		return data
	}

	// HAP encrypted frame format: split plaintext into max 1024-byte chunks.
	// Each chunk: [2-byte LE plaintext length][encrypted(plaintext) + 16-byte Poly1305 tag]
	// AAD for each chunk is the 2-byte length prefix.
	var result []byte
	chunkNum := 0
	for len(data) > 0 {
		chunk := data
		if len(chunk) > 1024 {
			chunk = chunk[:1024]
		}
		data = data[len(chunk):]

		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonce[4:], c.encWriteNonce)

		aad := make([]byte, 2)
		binary.LittleEndian.PutUint16(aad, uint16(len(chunk)))

		dbg("[ENC-WRITE] chunk %d: %d bytes, writeNonce=%d, aad=%s",
			chunkNum, len(chunk), c.encWriteNonce, hex.EncodeToString(aad))
		c.encWriteNonce++

		encrypted := c.encCipher.Seal(nil, nonce, chunk, aad)

		result = append(result, aad...)
		result = append(result, encrypted...)
		chunkNum++
	}
	dbg("[ENC-WRITE] total: %d chunks, %d bytes output", chunkNum, len(result))
	return result
}

// readEncryptedFrame reads and decrypts one HAP encrypted frame from the connection.
func (c *AirPlayClient) readEncryptedFrame() ([]byte, error) {
	// Read 2-byte LE length
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read frame length: %w (timeout or connection closed)", err)
	}
	plaintextLen := int(binary.LittleEndian.Uint16(lengthBuf))
	dbg("[ENC-FRAME] length prefix: %s (plaintext len=%d, will read %d bytes)",
		hex.EncodeToString(lengthBuf), plaintextLen, plaintextLen+16)

	if plaintextLen == 0 || plaintextLen > 16384 {
		dbg("[ENC-FRAME] WARNING: suspicious frame length %d — raw bytes on wire may not be encrypted frames", plaintextLen)
		// Peek at a few more bytes for debugging
		peek := make([]byte, 32)
		n, _ := c.conn.Read(peek)
		dbg("[ENC-FRAME] next %d bytes on wire: %s", n, hex.EncodeToString(peek[:n]))
		return nil, fmt.Errorf("suspicious frame length %d (expected 1-1024)", plaintextLen)
	}

	// Read ciphertext (plaintext length + 16-byte Poly1305 tag)
	ciphertext := make([]byte, plaintextLen+16)
	if _, err := io.ReadFull(c.conn, ciphertext); err != nil {
		return nil, fmt.Errorf("read frame ciphertext (%d bytes): %w", plaintextLen+16, err)
	}

	// Decrypt
	readCipher, err := chacha20poly1305.New(c.encReadKey)
	if err != nil {
		return nil, fmt.Errorf("read cipher: %w", err)
	}

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], c.encReadNonce)
	dbg("[ENC-FRAME] decrypting with nonce=%d key=%s... aad=%s",
		c.encReadNonce, hex.EncodeToString(c.encReadKey[:8]), hex.EncodeToString(lengthBuf))
	c.encReadNonce++

	plaintext, err := readCipher.Open(nil, nonce, ciphertext, lengthBuf)
	if err != nil {
		dbg("[ENC-FRAME] DECRYPT FAILED: nonce=%d ciphertext[:32]=%s",
			c.encReadNonce-1, hex.EncodeToString(ciphertext[:min(32, len(ciphertext))]))
		return nil, fmt.Errorf("decrypt frame (nonce=%d, len=%d): %w", c.encReadNonce-1, plaintextLen, err)
	}

	dbg("[ENC-FRAME] decrypted %d bytes OK", len(plaintext))
	return plaintext, nil
}

// readDecryptedBytes reads and decrypts enough bytes from the encrypted channel.
func (c *AirPlayClient) readDecryptedBytes(n int) ([]byte, error) {
	var buf []byte
	for len(buf) < n {
		frame, err := c.readEncryptedFrame()
		if err != nil {
			return nil, err
		}
		buf = append(buf, frame...)
	}
	return buf[:n], nil
}

// StreamConfig holds the configuration for a mirroring session.
type StreamConfig struct {
	FPS                    int
	Bitrate                int           // Video bitrate in kbps
	VideoCodec             VideoCodec    // empty/h264, auto, or capability-gated hevc
	AutomaticHEVCAvailable bool          // capture preflight found the hardware HEVC-4K path
	MeasuredVideoLatency   time.Duration // measured minimum lead for the local HEVC capture path
	MinimumVideoLead       time.Duration // known capture/transport lead before codec selection
	NoEncrypt              bool          // Disable encryption for debugging
	DirectKey              bool          // Use shk/shiv directly without SHA-512 derivation
	NoAudio                bool          // Disable audio streaming

	// PortMin/PortMax bound the local ports used for the audio UDP triple
	// (timing/control/data, 3 consecutive ports). The receiver's event channel
	// is an outbound TCP connection and does not consume this range. When both
	// are zero the OS chooses ephemeral ports.
	PortMin int
	PortMax int
}

// generateStreamKey creates a random AES-128 key for stream encryption.
func generateStreamKey() (key, iv []byte, err error) {
	key = make([]byte, 16)
	iv = make([]byte, 16)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, err
	}
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

// newStreamCipher creates an AES-CTR cipher for stream encryption.
func newStreamCipher(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// mirrorCipher implements the AirPlay mirroring AES-CTR encryption scheme
// matching the receiver's mirror_buffer_decrypt exactly.
//
// The receiver (mirror_buffer.c) processes each frame as follows:
//  1. XOR the first nextDecryptCount bytes using cached keystream (og buffer)
//     left over from the previous frame's trailing partial block.
//  2. Call aes_ctr_start_fresh_block — advance CTR to next 16-byte boundary.
//  3. Decrypt floor((len - nextDecryptCount) / 16) * 16 bytes (full blocks).
//  4. If trailing partial block: pad to 16, decrypt full block, use needed
//     bytes, cache remaining keystream in og for step 1 of next frame.
//
// The sender must produce ciphertext that decrypts correctly under this scheme.
type mirrorCipher struct {
	stream         cipher.Stream
	blockOffset    int      // bytes consumed in current 16-byte CTR block
	og             [16]byte // cached keystream from previous frame's trailing partial block
	nextCryptCount int      // how many og bytes are available for the next frame's prefix
}

func newMirrorCipher(key, iv []byte) (*mirrorCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &mirrorCipher{
		stream: cipher.NewCTR(block, iv),
	}, nil
}

// EncryptFrame encrypts a single video frame payload, matching the
// receiver's mirror_buffer_decrypt block-alignment scheme.
func (mc *mirrorCipher) EncryptFrame(payload []byte) []byte {
	inputLen := len(payload)
	out := make([]byte, inputLen)
	pos := 0

	// Step 1: XOR prefix bytes using cached keystream from previous frame's
	// trailing partial block (matches receiver's og buffer usage).
	if mc.nextCryptCount > 0 {
		available := mc.nextCryptCount
		n := available
		if n > inputLen {
			n = inputLen
		}
		ogStart := 16 - available
		for i := 0; i < n; i++ {
			out[i] = payload[i] ^ mc.og[ogStart+i]
		}
		pos = n
		if n < available {
			// A small frame may consume only part of the cached block. Preserve
			// its unused suffix for the next frame instead of advancing CTR early.
			remaining := available - n
			copy(mc.og[16-remaining:], mc.og[ogStart+n:])
			mc.nextCryptCount = remaining
			return out
		}
		mc.nextCryptCount = 0
	}

	// Step 2: Advance CTR to next 16-byte boundary (aes_ctr_start_fresh_block).
	if mc.blockOffset > 0 {
		waste := make([]byte, 16-mc.blockOffset)
		mc.stream.XORKeyStream(waste, waste)
		mc.blockOffset = 0
	}

	remaining := inputLen - pos

	// Step 3: Encrypt full 16-byte blocks.
	fullBlocks := (remaining / 16) * 16
	if fullBlocks > 0 {
		mc.stream.XORKeyStream(out[pos:pos+fullBlocks], payload[pos:pos+fullBlocks])
		mc.blockOffset = 0 // still aligned after full blocks
		pos += fullBlocks
	}

	// Step 4: Handle trailing partial block.
	restLen := remaining % 16
	if restLen > 0 {
		// Pad input to 16 bytes, encrypt full block, use first restLen bytes.
		var padded [16]byte
		copy(padded[:restLen], payload[pos:pos+restLen])
		mc.stream.XORKeyStream(padded[:], padded[:])
		copy(out[pos:], padded[:restLen])
		// Cache the full decrypted block for next frame's step 1.
		mc.og = padded
		mc.nextCryptCount = 16 - restLen
		mc.blockOffset = 0 // we encrypted a full 16-byte block
	}

	return out
}

// maxResponseBody bounds what a receiver can make the sender allocate from a
// Content-Length header. Control-channel bodies here are small plists; this is
// far above anything legitimate and far below anything that would exhaust
// memory.
const maxResponseBody = 8 << 20

// validateContentLength rejects a Content-Length the sender cannot safely act
// on. A negative value is the important one: it reaches make([]byte, n) and
// panics with "makeslice: len out of range", so a receiver answering
// "Content-Length: -1" crashes the sender outright.
func validateContentLength(n int) error {
	if n < 0 {
		return fmt.Errorf("invalid negative Content-Length %d", n)
	}
	if n > maxResponseBody {
		return fmt.Errorf("Content-Length %d exceeds the %d byte limit", n, maxResponseBody)
	}
	return nil
}
