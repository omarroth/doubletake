package airplay

import (
	"encoding/hex"
	"testing"

	"howett.net/plist"
)

func decodeInfo(t *testing.T, info map[string]interface{}) ReceiverInfo {
	t.Helper()
	body, err := plist.Marshal(info, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ReceiverInfo
	if _, err := plist.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return got
}

func TestReceiverInfoAcceptsEitherEncoding(t *testing.T) {
	pk := make([]byte, 32)
	for i := range pk {
		pk[i] = byte(i)
	}

	strict := map[string]interface{}{
		"pk":                       pk,
		"keepAliveSendStatsAsBody": true,
		"displays": []interface{}{map[string]interface{}{
			"widthPixels": uint64(1920), "heightPixels": uint64(1080),
		}},
	}
	loose := map[string]interface{}{
		"pk":                       hex.EncodeToString(pk),
		"keepAliveSendStatsAsBody": uint64(1),
		"displays": []interface{}{map[string]interface{}{
			"widthPixels": 1920.0, "heightPixels": 1080.0,
		}},
	}

	for name, info := range map[string]map[string]interface{}{
		"strict": strict,
		"loose":  loose,
	} {
		t.Run(name, func(t *testing.T) {
			got := decodeInfo(t, info)
			if hex.EncodeToString(got.PK) != hex.EncodeToString(pk) {
				t.Errorf("PK = %x, want %x", got.PK, pk)
			}
			if !got.KeepAliveBody {
				t.Error("KeepAliveBody = false, want true")
			}
			if w, h := got.DisplaySize(); w != 1920 || h != 1080 {
				t.Errorf("DisplaySize() = %dx%d, want 1920x1080", w, h)
			}
		})
	}
}

func TestReceiverInfoRejectsUndecodablePK(t *testing.T) {
	body, err := plist.Marshal(map[string]interface{}{"pk": "not hex"}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ReceiverInfo
	if _, err := plist.Unmarshal(body, &got); err == nil {
		t.Fatal("expected an error for a pk that is neither data nor hex")
	}
}
