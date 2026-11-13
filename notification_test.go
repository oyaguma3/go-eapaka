package eapaka

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAtNotification_FullCode(t *testing.T) {
	tests := []struct {
		name string
		attr AtNotification
		want uint16
	}{
		{"general_failure_after_auth", AtNotification{}, NotificationGeneralFailureAfterAuth},
		{"temporarily_denied", AtNotification{Code: 1026}, NotificationTemporarilyDenied},
		{"not_subscribed", AtNotification{Code: 1031}, NotificationNotSubscribed},
		{"general_failure", AtNotification{P: true}, NotificationGeneralFailure},
		{"success", AtNotification{S: true}, NotificationSuccess},
		// Code の上位 2 bit は使わず、S と P だけで決まる
		{"code_upper_bits_ignored", AtNotification{Code: 0xC000 | 1026}, NotificationTemporarilyDenied},
		{"s_and_p", AtNotification{S: true, P: true, Code: 1}, 0xC001},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.attr.FullCode(); got != tt.want {
				t.Errorf("FullCode() = %d (0x%04x), want %d (0x%04x)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestNewNotification(t *testing.T) {
	tests := []struct {
		name string
		code uint16
		want AtNotification
	}{
		{"general_failure_after_auth", NotificationGeneralFailureAfterAuth, AtNotification{}},
		{"temporarily_denied", NotificationTemporarilyDenied, AtNotification{Code: 1026}},
		{"not_subscribed", NotificationNotSubscribed, AtNotification{Code: 1031}},
		{"general_failure", NotificationGeneralFailure, AtNotification{P: true}},
		{"success", NotificationSuccess, AtNotification{S: true}},
		// RFC 4187 §6.1 では許されない組み合わせ（P=1 なら S=0）も、そのまま表す
		{"s_and_p", 0xC001, AtNotification{S: true, P: true, Code: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewNotification(tt.code)
			if diff := cmp.Diff(&tt.want, got); diff != "" {
				t.Errorf("NewNotification(%d) mismatch (-want +got):\n%s", tt.code, diff)
			}
			if fc := got.FullCode(); fc != tt.code {
				t.Errorf("FullCode() = %d, want %d", fc, tt.code)
			}

			// ワイヤ上の値は 16 bit のコード値そのもので、解析すると元に戻る
			b, err := got.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			wantWire := []byte{byte(AT_NOTIFICATION), 1, byte(tt.code >> 8), byte(tt.code)}
			if diff := cmp.Diff(wantWire, b); diff != "" {
				t.Errorf("Marshal mismatch (-want +got):\n%s", diff)
			}
			attrs, err := ParseAttributes(b)
			if err != nil {
				t.Fatalf("ParseAttributes: %v", err)
			}
			if diff := cmp.Diff([]Attribute{got}, attrs); diff != "" {
				t.Errorf("parsed attribute mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestAtNotification_HostapPackets は、hostap が組み立てた EAP-Request/AKA-Notification
// （0「General failure after authentication」）の AT_NOTIFICATION を読み取れることを確かめる。
func TestAtNotification_HostapPackets(t *testing.T) {
	n := 0
	for _, v := range loadVectors[packetVector](t, "packets.json") {
		p, err := Parse(v.Packet)
		if err != nil {
			t.Fatalf("%s: Parse: %v", v.Name, err)
		}
		if p.Code != CodeRequest || p.Subtype != SubtypeNotification {
			continue
		}
		n++
		t.Run(v.Name, func(t *testing.T) {
			var notif *AtNotification
			for _, a := range p.Attributes {
				if a, ok := a.(*AtNotification); ok {
					notif = a
				}
			}
			if notif == nil {
				t.Fatal("AT_NOTIFICATION not found")
			}
			if got := notif.FullCode(); got != NotificationGeneralFailureAfterAuth {
				t.Errorf("FullCode() = %d, want %d", got, NotificationGeneralFailureAfterAuth)
			}
			if notif.S || notif.P {
				t.Errorf("S, P = %v, %v, want false, false", notif.S, notif.P)
			}
		})
	}
	if n == 0 {
		t.Fatal("no EAP-Request/AKA-Notification vector")
	}
}
