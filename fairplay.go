package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"airplay/playfair"
)

const message2KnownHexA = "46504c59030102000000008202026d43aba911971ca3a31837c8678d73ec8daa1c99a5960ae1853866ebec1143ee3ef27439ac9389bc7deb91993e4d8538e5447882e1dbe91aff0e4fdf7d5f520cd598ab59ae95f1ee47cae087c6820a117d2a6254401496397554d3d1daf4f456851380df949888cc5df2508f992d27b256846d553d571f291a11813c2bb85674"
const message3KnownHexA = "46504c590301030000000098028f1a9cf3fc90b2eea0fd8443827de1bdb9bdf37028c539bb763dbda6fe6b90ef42fa8e8fa15f1788f4377a72d274e1fcbb508f00e2af99e506626340a07df4b56f2368e653817d2fac9c9109c5d289b5d228d0c1a7a912f12bdb4332c6b91a6f61cade842c0f5378a578278f6299e74c3d39ad2adc9acf629d23fa118e852e31dfa8b6bf28e7af103534c3693fabcd645c186de254c25d"
const message2KnownHexB = "46504c5903010200000000820202394e579078c4e34a271507d063ec4d514030353d82a334b68f9d53173dad94a6b68e459e2741c09f31ca2fc81f67777eb323fce71fe98caedea51e4039ed2a3fbc7a684e77647ffd8351556308f5cd00c35d42811ba74bf5811d47c6568558458f94409c3b143b540a1f75c639520f89748132235af6fda272391fa6c1c341a9"
const message3KnownHexB = "46504c590301030000000098028f1a9ccb57beb1e5756eb26955eb4aed866ebd10f3c860880ede87b42eedc0ce799758d9f9b8fdb01470adb129e81c380d1fbf2fb5769f0f800f1033340b8b40feb6369447644706f67919dff86a5638cbd5e82f1666b144df970b824c03406322e43dc61410c8c0fc82c9a422ed92ede12eab6bdcae7e3be469ecc9a24077648be5280b2e309ac0a0cc40859b5e6962c03da559736ead"

type fpMessageCandidate struct {
	Name    string
	Message [164]byte
}

// FairPlay SAP (Secure Association Protocol) setup for AirPlay screen mirroring.
// Establishes the AES key used to encrypt the video stream via a 2-round handshake
// with the receiver, then wraps the key in a 72-byte ekey using the playfair cipher.
//
// Protocol:
//   Phase 1: Client sends 16-byte hello (type 1), server responds with 142 bytes (type 2)
//   Phase 2: Client sends 164-byte key exchange (type 3), server echoes last 20 bytes (type 4)
//   SETUP:   Client sends ekey (72 bytes) + eiv (16 bytes) + et=32 in the stream descriptor

func (c *AirPlayClient) fairPlaySetup(ctx context.Context) error {
	// Use the Wine + AirParrotNative.dll harness for real FairPlay SAP
	m1, m3, phase2Resp, err := c.fairPlayViaHarness(ctx)
	if err != nil {
		return err
	}

	// Generate a random 16-byte AES key for stream encryption
	var plainKey [16]byte
	if _, err := rand.Read(plainKey[:]); err != nil {
		return fmt.Errorf("generate stream key: %w", err)
	}

	// Wrap the key into a 72-byte ekey using the playfair cipher
	_ = m1
	ekey := playfair.Encrypt(m3, plainKey)

	// Verify round-trip: decrypt ekey and confirm we get plainKey back
	recovered := playfair.Decrypt(m3, ekey)
	if recovered != plainKey {
		log.Printf("[FP] WARNING: playfair round-trip FAILED! encrypt→decrypt mismatch")
		log.Printf("[FP]   plainKey:  %02x", plainKey)
		log.Printf("[FP]   recovered: %02x", recovered)
	} else {
		log.Printf("[FP] playfair round-trip OK: encrypt→decrypt matches plainKey")
	}

	// Use FP phase 2 response as session key (Apple TV derives keys from this, not from ekey)
	// The first 16 bytes of the phase 2 response are used as the audio AES key
	var sessionKey [16]byte
	copy(sessionKey[:], phase2Resp[:16])
	log.Printf("[FP] phase2Resp session key: %02x", sessionKey)
	log.Printf("[FP] playfair plainKey:      %02x", plainKey)

	// Generate a random 16-byte IV
	var eiv [16]byte
	if _, err := rand.Read(eiv[:]); err != nil {
		return fmt.Errorf("generate stream IV: %w", err)
	}

	// Store the FairPlay results
	// Try BOTH approaches:
	// A) plainKey (random, wrapped in ekey) - receiver uses fairplay_decrypt(m3, ekey) to get plainKey
	// B) sessionKey (from phase2Resp[:16]) - receiver uses FP internal state
	// For now, try A with combined hash since ekey is at root level
	c.fpKey = plainKey[:]
	c.fpIV = eiv[:]
	c.fpEkey = ekey[:]

	log.Printf("[FP] setup complete: ekey=%d bytes, eiv=%02x", len(c.fpEkey), c.fpIV)
	return nil
}

// fairPlayViaHarness runs the Wine-based FairPlay harness to perform the
// real FP_Init / FP_Process handshake with the Apple TV.
func (c *AirPlayClient) fairPlayViaHarness(ctx context.Context) (m1 []byte, m3 [164]byte, phase2Resp []byte, err error) {
	// Find the harness relative to the executable
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	harnessExe := filepath.Join(dir, "fp_harness.exe")

	log.Printf("[FP] starting Wine harness: %s", harnessExe)

	cmd := exec.CommandContext(ctx, "wine", harnessExe)
	cmd.Dir = dir // DLL is in same directory

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, m3, nil, fmt.Errorf("harness stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, m3, nil, fmt.Errorf("harness stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, m3, nil, fmt.Errorf("harness start: %w", err)
	}
	defer cmd.Wait()

	scanner := bufio.NewScanner(stdout)

	// Read Phase 1 output: "PHASE1=<hex>" (skip any Wine/DLL debug output)
	var m1Hex string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ERROR=") {
			return nil, m3, nil, fmt.Errorf("harness phase 1 error: %s", line[6:])
		}
		if strings.HasPrefix(line, "PHASE1=") {
			m1Hex = line[7:]
			break
		}
		// Skip Wine debug output
		log.Printf("[FP] harness debug: %s", line)
	}
	if m1Hex == "" {
		return nil, m3, nil, fmt.Errorf("harness: no PHASE1 output")
	}
	m1, err = hex.DecodeString(m1Hex)
	if err != nil {
		return nil, m3, nil, fmt.Errorf("decode phase 1 hex: %w", err)
	}
	log.Printf("[FP] phase 1: harness generated %d bytes", len(m1))

	// POST m1 to Apple TV
	phase1Resp, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		stdin.Close()
		return nil, m3, nil, fmt.Errorf("fp-setup phase 1: %w", err)
	}
	log.Printf("[FP] phase 1: server response %d bytes", len(phase1Resp))

	if len(phase1Resp) < 12 || phase1Resp[6] != 2 {
		stdin.Close()
		return nil, m3, nil, fmt.Errorf("fp-setup phase 1: bad response (len=%d)", len(phase1Resp))
	}

	// Feed m2 to harness
	m2Hex := hex.EncodeToString(phase1Resp)
	log.Printf("[FP] phase 2: feeding %d-byte m2 to harness", len(phase1Resp))
	fmt.Fprintf(stdin, "%s\n", m2Hex)
	stdin.Close()

	// Read Phase 2 output: "PHASE2=<hex>" (skip any Wine/DLL debug output)
	var m3Hex string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PHASE2_ERR=") {
			return nil, m3, nil, fmt.Errorf("harness phase 2 error: %s", line)
		}
		if strings.HasPrefix(line, "ERROR=") {
			return nil, m3, nil, fmt.Errorf("harness error: %s", line[6:])
		}
		if strings.HasPrefix(line, "PHASE2=") {
			m3Hex = line[7:]
			break
		}
		log.Printf("[FP] harness debug: %s", line)
	}
	if m3Hex == "" {
		return nil, m3, nil, fmt.Errorf("harness: no PHASE2 output")
	}
	m3Bytes, err := hex.DecodeString(m3Hex)
	if err != nil {
		return nil, m3, nil, fmt.Errorf("decode phase 2 hex: %w", err)
	}
	if len(m3Bytes) != 164 {
		return nil, m3, nil, fmt.Errorf("phase 2: expected 164 bytes, got %d", len(m3Bytes))
	}
	copy(m3[:], m3Bytes)
	log.Printf("[FP] phase 2: harness generated 164-byte m3")

	// POST m3 to Apple TV
	phase2Resp, err = c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3[:],
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return nil, m3, nil, fmt.Errorf("fp-setup phase 2: %w", err)
	}
	log.Printf("[FP] phase 2: server response %d bytes", len(phase2Resp))

	if len(phase2Resp) >= 32 && phase2Resp[6] == 4 {
		log.Printf("[FP] phase 2: server accepted! response type=%d", phase2Resp[6])
		log.Printf("[FP] phase 2: response hex=%02x", phase2Resp)
	} else {
		return nil, m3, nil, fmt.Errorf("fp-setup phase 2: rejected (len=%d, type=%d)",
			len(phase2Resp), func() byte {
				if len(phase2Resp) > 6 {
					return phase2Resp[6]
				}
				return 0
			}())
	}

	return m1, m3, phase2Resp, nil
}

// deriveStreamKeys derives AES stream encryption keys from the pair-verify shared secret.
// This is used when FairPlay setup is skipped (HomeKit Pairing provides sufficient auth).
func (c *AirPlayClient) deriveStreamKeys() error {
	if c.encWriteKey == nil {
		// Generate random stream key if no pair-verify keys available
		key, iv, err := generateStreamKey()
		if err != nil {
			return err
		}
		c.streamKey = key
		c.streamIV = iv
		return nil
	}

	// Derive from pair-verify encryption key using HKDF
	derived := hkdfSHA512(c.encWriteKey, []byte("AirPlayStream-Salt"), []byte("AirPlayStream-Key"), 32)
	c.streamKey = derived[:16]
	c.streamIV = derived[16:32]
	return nil
}

func buildFPMessage(phase byte, payload []byte) []byte {
	msg := make([]byte, 12+len(payload))
	copy(msg[0:4], []byte("FPLY"))
	msg[4] = 0x03
	msg[5] = 0x01
	msg[6] = phase
	msg[7] = 0x00
	msg[8] = byte(len(payload) >> 24)
	msg[9] = byte(len(payload) >> 16)
	msg[10] = byte(len(payload) >> 8)
	msg[11] = byte(len(payload))
	copy(msg[12:], payload)
	return msg
}

func sha1Hash(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

func decode164Hex(hexStr string) ([164]byte, error) {
	var out [164]byte
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return out, err
	}
	if len(b) != len(out) {
		return out, fmt.Errorf("decoded %d bytes, want %d", len(b), len(out))
	}
	copy(out[:], b)
	return out, nil
}

func decode142Hex(hexStr string) ([142]byte, error) {
	var out [142]byte
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return out, err
	}
	if len(b) != len(out) {
		return out, fmt.Errorf("decoded %d bytes, want %d", len(b), len(out))
	}
	copy(out[:], b)
	return out, nil
}

func buildPhase2Candidates(phase1Resp []byte) ([]fpMessageCandidate, error) {
	candidates := make([]fpMessageCandidate, 0, 4)

	// Build a standard type-3 FPLY header template
	var tmpl [164]byte
	copy(tmpl[0:4], []byte("FPLY"))
	tmpl[4] = 0x03
	tmpl[5] = 0x01
	tmpl[6] = 0x03
	tmpl[7] = 0x00
	tmpl[8] = 0x00
	tmpl[9] = 0x00
	tmpl[10] = 0x00
	tmpl[11] = 0x98 // payload length = 152
	tmpl[12] = 0x02 // mode
	tmpl[13] = 0x8f
	tmpl[14] = 0x1a
	tmpl[15] = 0x9c

	if len(phase1Resp) >= 142 {
		// Decrypt the m2 body to get the challenge plaintext
		var m2as164 [164]byte
		m2as164[12] = phase1Resp[12] // mode byte
		copy(m2as164[16:144], phase1Resp[14:142])
		m2plain := playfair.DecryptMessage(m2as164)

		// Strategy: decrypt m2, re-encrypt as m3 with 0001 prefix, zero tag
		{
			var msg [164]byte
			copy(msg[:], tmpl[:])
			enc := playfair.EncryptMessage(msg, m2plain)
			// Try SHA1 of encrypted body as tag
			tag := sha1Hash(enc[16:144])
			copy(enc[144:164], tag)
			candidates = append(candidates, fpMessageCandidate{Name: "reenc-m2-sha1tag", Message: enc})
		}

		// Strategy: random plaintext with 0001 prefix, zero tag
		{
			var plain [128]byte
			plain[0] = 0x00
			plain[1] = 0x01
			rand.Read(plain[2:])
			var msg [164]byte
			copy(msg[:], tmpl[:])
			enc := playfair.EncryptMessage(msg, plain)
			candidates = append(candidates, fpMessageCandidate{Name: "random-0001-zerotag", Message: enc})
		}

		// Strategy: echo m2 body directly (ciphertext), zero tag
		{
			var msg [164]byte
			copy(msg[:], tmpl[:])
			copy(msg[16:144], phase1Resp[14:142])
			candidates = append(candidates, fpMessageCandidate{Name: "echo-m2-body", Message: msg})
		}

		// Diagnostic: all zeros body (tests whether error changes)
		{
			var msg [164]byte
			copy(msg[:], tmpl[:])
			candidates = append(candidates, fpMessageCandidate{Name: "zeros-body-diag", Message: msg})
		}

		log.Printf("[FP] m2 mode=%02x sub=%02x", phase1Resp[12], phase1Resp[13])
		log.Printf("[FP] m2 plaintext[0:8]: %02x", m2plain[:8])
	}

	return candidates, nil
}
