package airplay

import "testing"

func TestParseDigestChallenge(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantOK    bool
		wantRealm string
		wantNonce string
	}{
		{
			// Verbatim from an AppleTV14,1 running AirTunes/950.7.1 with
			// "Require Password" enabled: no qop, no algorithm, base64 nonce.
			name:      "apple tv challenge",
			value:     `Digest realm="airplay", nonce="MTc4NTE4NjAxMCD20F7TBLQS+AiSlk1YQmKR"`,
			wantOK:    true,
			wantRealm: "airplay",
			wantNonce: "MTc4NTE4NjAxMCD20F7TBLQS+AiSlk1YQmKR",
		},
		{
			name:      "raop realm",
			value:     `Digest realm="raop", nonce="deadbeef"`,
			wantOK:    true,
			wantRealm: "raop",
			wantNonce: "deadbeef",
		},
		{
			name:      "lowercase scheme and extra whitespace",
			value:     `  digest   realm="airplay" ,  nonce="abc"  `,
			wantOK:    true,
			wantRealm: "airplay",
			wantNonce: "abc",
		},
		{
			// A comma inside a quoted value must not split the parameter.
			name:      "comma inside quoted nonce",
			value:     `Digest realm="airplay", nonce="aa,bb", algorithm=MD5`,
			wantOK:    true,
			wantRealm: "airplay",
			wantNonce: "aa,bb",
		},
		{
			name:   "basic scheme is not digest",
			value:  `Basic realm="airplay"`,
			wantOK: false,
		},
		{
			name:   "missing nonce",
			value:  `Digest realm="airplay"`,
			wantOK: false,
		},
		{
			name:   "missing realm",
			value:  `Digest nonce="abc"`,
			wantOK: false,
		},
		{
			// What a 401 with no WWW-Authenticate header looks like after a
			// nil-map lookup.
			name:   "empty",
			value:  "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, ok := parseDigestChallenge(tt.value)
			if ok != tt.wantOK {
				t.Fatalf("parseDigestChallenge(%q) ok = %v, want %v", tt.value, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if ch.Realm != tt.wantRealm {
				t.Errorf("realm = %q, want %q", ch.Realm, tt.wantRealm)
			}
			if ch.Nonce != tt.wantNonce {
				t.Errorf("nonce = %q, want %q", ch.Nonce, tt.wantNonce)
			}
		})
	}
}

func TestDigestResponse(t *testing.T) {
	// Expected value computed independently:
	//   HA1      = md5("AirPlay:airplay:secret")
	//   HA2      = md5("SETUP:rtsp://192.168.1.246/1234")
	//   response = md5(HA1:abc123:HA2)
	const want = "62160c3ff2f72dacd546c8c5135eba4b"

	got := digestResponse("AirPlay", "airplay", "secret", "abc123", "SETUP", "rtsp://192.168.1.246/1234")
	if got != want {
		t.Errorf("digestResponse() = %q, want %q", got, want)
	}
}

func TestDigestResponseVariesWithCredentials(t *testing.T) {
	base := digestResponse("AirPlay", "airplay", "secret", "abc123", "SETUP", "rtsp://host/1")

	// The username is folded into HA1, so getting it wrong fails exactly like a
	// wrong password -- which is why DigestUsername is fixed rather than
	// guessed: a bad guess is indistinguishable from a bad password.
	if other := digestResponse("iTunes", "airplay", "secret", "abc123", "SETUP", "rtsp://host/1"); other == base {
		t.Error("response did not change with a different username")
	}
	if other := digestResponse("AirPlay", "airplay", "wrong", "abc123", "SETUP", "rtsp://host/1"); other == base {
		t.Error("response did not change with a different password")
	}
	// HA2 covers method and URI, so a replayed header cannot authorise a
	// different request.
	if other := digestResponse("AirPlay", "airplay", "secret", "abc123", "RECORD", "rtsp://host/1"); other == base {
		t.Error("response did not change with a different method")
	}
	if other := digestResponse("AirPlay", "airplay", "secret", "abc123", "SETUP", "rtsp://host/2"); other == base {
		t.Error("response did not change with a different uri")
	}
	if other := digestResponse("AirPlay", "airplay", "secret", "different", "SETUP", "rtsp://host/1"); other == base {
		t.Error("response did not change with a different nonce")
	}
}

func TestAuthorizationHeader(t *testing.T) {
	ch := &digestChallenge{Realm: "airplay", Nonce: "abc123"}
	got := authorizationHeader("AirPlay", "secret", ch, "SETUP", "rtsp://192.168.1.246/1234")
	want := `Digest username="AirPlay", realm="airplay", nonce="abc123", uri="rtsp://192.168.1.246/1234", ` +
		`response="` + digestResponse("AirPlay", "airplay", "secret", "abc123", "SETUP", "rtsp://192.168.1.246/1234") + `"`
	if got != want {
		t.Errorf("authorizationHeader() =\n  %q\nwant\n  %q", got, want)
	}
}

func TestWithHeaderDoesNotMutateOriginal(t *testing.T) {
	original := map[string]string{"X-Existing": "1"}
	out := withHeader(original, "Authorization", "Digest ...")

	if _, ok := original["Authorization"]; ok {
		t.Error("withHeader mutated the caller's map; a stale nonce would leak into later requests")
	}
	if out["X-Existing"] != "1" || out["Authorization"] != "Digest ..." {
		t.Errorf("withHeader produced %v", out)
	}
	if nilOut := withHeader(nil, "Authorization", "x"); nilOut["Authorization"] != "x" {
		t.Error("withHeader did not handle a nil map")
	}
}

func TestDigestRetryHeader(t *testing.T) {
	challenge := map[string]string{
		"www-authenticate": `Digest realm="airplay", nonce="abc123"`,
	}
	unauthorized := &HTTPStatusError{StatusCode: 401}

	tests := []struct {
		name     string
		password string
		headers  map[string]string
		err      error
		wantOK   bool
	}{
		{name: "success is not retried", password: "secret", headers: challenge, err: nil, wantOK: false},
		{name: "non-401 is not retried", password: "secret", headers: challenge, err: &HTTPStatusError{StatusCode: 500}, wantOK: false},
		{
			// The case that silently did nothing before: a challenge arrives,
			// no password is configured, and the bare 401 surfaces.
			name: "401 with challenge but no password", password: "", headers: challenge, err: unauthorized, wantOK: false,
		},
		{name: "401 without a challenge header", password: "secret", headers: map[string]string{}, err: unauthorized, wantOK: false},
		{name: "401 with nil headers", password: "secret", headers: nil, err: unauthorized, wantOK: false},
		{name: "401 with challenge and password", password: "secret", headers: challenge, err: unauthorized, wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &AirPlayClient{authPassword: tt.password}
			hdr, ok := c.digestRetryHeader("SETUP", "rtsp://host/1", tt.headers, tt.err)
			if ok != tt.wantOK {
				t.Fatalf("digestRetryHeader ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			want := authorizationHeader(DigestUsername, tt.password,
				&digestChallenge{Realm: "airplay", Nonce: "abc123"}, "SETUP", "rtsp://host/1")
			if hdr != want {
				t.Errorf("header =\n  %q\nwant\n  %q", hdr, want)
			}
		})
	}
}
