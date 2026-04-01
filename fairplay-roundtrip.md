# FairPlay Roundtrip Notes

## Summary

This repo now includes a local client/server FairPlay roundtrip verification in Go tests:

- `TestFairPlayLocalRoundtripClientServer`
- `TestFairPlayKeyMustNotBeMixedWithPairVerifySecret`

These tests validate that the stream key recovered from `ekey` is the same key used to derive video AES-CTR keys, and that this keying model decrypts frames end-to-end using the same block alignment behavior as the receiver.

## Expected Flow

1. `POST /fp-setup` phase 1:
- client sends `m1` (type 1)
- receiver returns `m2` (type 2)

2. `POST /fp-setup` phase 2:
- client sends `m3` (type 3)
- receiver returns `m4` (type 4)

3. During `SETUP`:
- client sends root-level `ekey` (72 bytes) and `eiv` (16 bytes)
- receiver decrypts `ekey` using FairPlay state from phase 2 and obtains the audio/video base key (`shk` equivalent)

4. Video key derivation:
- both sides derive `AES-128-CTR` key/IV as:
  - `SHA-512("AirPlayStreamKey<streamConnectionID>" || fpKey)[:16]`
  - `SHA-512("AirPlayStreamIV<streamConnectionID>" || fpKey)[:16]`

5. Frame crypto:
- sender encrypts frames with receiver-compatible block boundary behavior (`mirror_buffer` semantics)
- receiver decrypts successfully when derivation key is exactly the FairPlay recovered key

## Fix Applied

File changed:
- `mirror.go`

Behavior change:
- removed FairPlay-mode key mixing with pair-verify shared secret (`SHA-512(fpKey || sharedSecret)[:16]`)
- always derive video keys directly from the FairPlay stream key in FairPlay mode

Why:
- receiver-side mirroring decrypt path expects keys derived from the FairPlay-recovered key
- mixing in pair-verify secret produces different keys and causes decrypt/authentication failure

## Local Validation

Run:

```bash
go test ./...
```

The new tests cover:

- local in-memory client/server FairPlay roundtrip using `playfair.Encrypt` + `playfair.Decrypt`
- multi-frame encryption/decryption verification across mixed frame sizes
- negative proof that mixed derivation (FairPlay key + pair-verify secret) breaks decryption

## AppleTV Validation

Use:

```bash
go build -o airplay . && ./airplay -target 192.168.1.77 -port 7000 -test
```

Look for absence of `kAuthenticationErr` / decrypt errors during sustained frame streaming.
