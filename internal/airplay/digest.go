package airplay

import (
	"crypto/md5" //nolint:gosec // MD5 is what RFC 2069 digest auth specifies; not our choice.
	"encoding/hex"
	"fmt"
	"strings"
)

// DigestUsername is the username AirPlay receivers expect in a Digest response.
// The challenge never carries a username, but it is folded into HA1, so a wrong
// value fails exactly like a wrong password: another 401. Receivers advertising
// realm="airplay" -- which is what a mirroring receiver advertises -- use
// "AirPlay".
const DigestUsername = "AirPlay"

// digestChallenge is a parsed WWW-Authenticate Digest challenge.
type digestChallenge struct {
	Realm string
	Nonce string
}

// parseDigestChallenge parses a WWW-Authenticate header value of the form
//
//	Digest realm="airplay", nonce="MTc4NTE4NjAxMCD20F7TBLQS+AiSlk1YQmKR"
//
// Apple TV sends neither qop nor algorithm, so this is the RFC 2069 flavour of
// digest rather than the RFC 2617 qop="auth" variant: no cnonce, no nc, and
// the response is a plain MD5(HA1:nonce:HA2).
func parseDigestChallenge(value string) (*digestChallenge, bool) {
	const scheme = "Digest"
	v := strings.TrimSpace(value)
	if len(v) < len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) {
		return nil, false
	}

	params := parseAuthParams(v[len(scheme):])
	realm, hasRealm := params["realm"]
	nonce, hasNonce := params["nonce"]
	if !hasRealm || !hasNonce {
		return nil, false
	}
	return &digestChallenge{Realm: realm, Nonce: nonce}, true
}

// parseAuthParams splits a comma-separated list of key="value" (or bare
// key=value) auth parameters. Quoted values are unquoted, and a comma inside
// quotes is kept rather than treated as a separator -- nonces are base64 and
// can contain characters that would otherwise confuse a naive split.
func parseAuthParams(s string) map[string]string {
	params := make(map[string]string)

	var key, val strings.Builder
	inKey, inQuotes := true, false

	flush := func() {
		k := strings.ToLower(strings.TrimSpace(key.String()))
		if k != "" {
			params[k] = strings.TrimSpace(val.String())
		}
		key.Reset()
		val.Reset()
		inKey = true
	}

	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case inQuotes && ch == '"':
			inQuotes = false
		case inQuotes:
			val.WriteByte(ch)
		case ch == '"' && !inKey:
			inQuotes = true
		case ch == '=' && inKey:
			inKey = false
		case ch == ',':
			flush()
		case inKey:
			key.WriteByte(ch)
		default:
			val.WriteByte(ch)
		}
	}
	flush()

	return params
}

// digestResponse computes the RFC 2069 digest response:
//
//	HA1      = MD5(username:realm:password)
//	HA2      = MD5(method:uri)
//	response = MD5(HA1:nonce:HA2)
func digestResponse(username, realm, password, nonce, method, uri string) string {
	ha1 := md5Hex(username + ":" + realm + ":" + password)
	ha2 := md5Hex(method + ":" + uri)
	return md5Hex(ha1 + ":" + nonce + ":" + ha2)
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // see file header
	return hex.EncodeToString(sum[:])
}

// authorizationHeader builds the Authorization header value that answers ch.
func authorizationHeader(username, password string, ch *digestChallenge, method, uri string) string {
	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, ch.Realm, ch.Nonce, uri,
		digestResponse(username, ch.Realm, password, ch.Nonce, method, uri),
	)
}
