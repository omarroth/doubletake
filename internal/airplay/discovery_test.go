package airplay

import "testing"

func TestUnescapeDNSName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "escaped punctuation",
			in:   "Living\\ Room\\ \\(2\\)",
			want: "Living Room (2)",
		},
		{
			name: "utf8 apostrophe encoded as decimal bytes",
			in:   "Emily\\226\\128\\153s MacBook Pro",
			want: "Emily’s MacBook Pro",
		},
		{
			name: "simple ascii apostrophe remains literal",
			in:   "Emily\\'s MacBook Pro",
			want: "Emily's MacBook Pro",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeDNSName(tt.in); got != tt.want {
				t.Fatalf("unescapeDNSName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSupportsFairPlaySAP(t *testing.T) {
	rokuFeatures := uint64(0x38bcf46007f8ad0)
	if (&ReceiverInfo{Features: rokuFeatures}).SupportsFairPlaySAP() {
		t.Fatalf("Roku feature mask unexpectedly advertises FPSAP")
	}
	if (&AirPlayDevice{Features: rokuFeatures}).SupportsFairPlaySAP() {
		t.Fatalf("Roku discovery feature mask unexpectedly advertises FPSAP")
	}

	withFairPlay := rokuFeatures | FeatureFPSAP25
	if !(&ReceiverInfo{Features: withFairPlay}).SupportsFairPlaySAP() {
		t.Fatalf("ReceiverInfo with FPSAP bit did not advertise FairPlay SAP")
	}
	if !(&AirPlayDevice{Features: withFairPlay}).SupportsFairPlaySAP() {
		t.Fatalf("AirPlayDevice with FPSAP bit did not advertise FairPlay SAP")
	}
}
