package eapaka

import (
	"bytes"
	"testing"
)

func TestAtRand_MarshalRFCLayout(t *testing.T) {
	rand := make([]byte, 16)
	for i := range rand {
		rand[i] = byte(i + 1)
	}

	got, err := (&AtRand{Rand: rand}).Marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	want := append([]byte{byte(AT_RAND), 0x05, 0x00, 0x00}, rand...)
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected AT_RAND bytes:\nwant=%x\ngot =%x", want, got)
	}
}

func TestAtRand_UnmarshalRFCLayout(t *testing.T) {
	wantRand := make([]byte, 16)
	for i := range wantRand {
		wantRand[i] = byte(i + 1)
	}

	data := append([]byte{0x00, 0x00}, wantRand...)
	attr := &AtRand{}
	if err := attr.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !bytes.Equal(attr.Rand, wantRand) {
		t.Fatalf("unexpected AT_RAND value:\nwant=%x\ngot =%x", wantRand, attr.Rand)
	}
}

func TestAtAutn_MarshalRFCLayout(t *testing.T) {
	autn := make([]byte, 16)
	for i := range autn {
		autn[i] = byte(i + 1)
	}

	got, err := (&AtAutn{Autn: autn}).Marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	want := append([]byte{byte(AT_AUTN), 0x05, 0x00, 0x00}, autn...)
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected AT_AUTN bytes:\nwant=%x\ngot =%x", want, got)
	}
}

func TestAtAutn_UnmarshalRFCLayout(t *testing.T) {
	wantAutn := make([]byte, 16)
	for i := range wantAutn {
		wantAutn[i] = byte(i + 1)
	}

	data := append([]byte{0x00, 0x00}, wantAutn...)
	attr := &AtAutn{}
	if err := attr.Unmarshal(data); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !bytes.Equal(attr.Autn, wantAutn) {
		t.Fatalf("unexpected AT_AUTN value:\nwant=%x\ngot =%x", wantAutn, attr.Autn)
	}
}

func TestAtCheckcode_LengthValidation(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		cases := []struct {
			name    string
			length  int
			wantErr bool
		}{
			{name: "zero", length: 0, wantErr: false},
			{name: "aka_20", length: 20, wantErr: false},
			{name: "aka_prime_32", length: 32, wantErr: false},
			{name: "invalid_16", length: 16, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := (&AtCheckcode{Checkcode: make([]byte, tc.length)}).Marshal()
				if tc.wantErr && err == nil {
					t.Fatal("expected error, got nil")
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		cases := []struct {
			name    string
			length  int
			wantErr bool
		}{
			{name: "zero", length: 0, wantErr: false},
			{name: "aka_20", length: 20, wantErr: false},
			{name: "aka_prime_32", length: 32, wantErr: false},
			{name: "invalid_16", length: 16, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				// Value part: Reserved(2) + Checkcode(length)
				data := make([]byte, 2+tc.length)
				attr := &AtCheckcode{}
				err := attr.Unmarshal(data)
				if tc.wantErr && err == nil {
					t.Fatal("expected error, got nil")
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !tc.wantErr && len(attr.Checkcode) != tc.length {
					t.Fatalf("unexpected checkcode length: want=%d got=%d", tc.length, len(attr.Checkcode))
				}
			})
		}
	})
}

func TestAtPadding_Validation(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		cases := []struct {
			name    string
			length  int
			wantErr bool
		}{
			{name: "len2", length: 2, wantErr: false},
			{name: "len6", length: 6, wantErr: false},
			{name: "len10", length: 10, wantErr: false},
			{name: "len4_invalid", length: 4, wantErr: true},
			{name: "negative_invalid", length: -1, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := (&AtPadding{Length: tc.length}).Marshal()
				if tc.wantErr && err == nil {
					t.Fatal("expected error, got nil")
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		cases := []struct {
			name    string
			data    []byte
			wantErr bool
		}{
			{name: "len2_zero", data: []byte{0x00, 0x00}, wantErr: false},
			{name: "len6_zero", data: []byte{0, 0, 0, 0, 0, 0}, wantErr: false},
			{name: "len10_zero", data: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, wantErr: false},
			{name: "len4_invalid", data: []byte{0, 0, 0, 0}, wantErr: true},
			{name: "non_zero_invalid", data: []byte{0x00, 0x01}, wantErr: true},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				attr := &AtPadding{}
				err := attr.Unmarshal(tc.data)
				if tc.wantErr && err == nil {
					t.Fatal("expected error, got nil")
				}
				if !tc.wantErr && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !tc.wantErr && attr.Length != len(tc.data) {
					t.Fatalf("unexpected length: want=%d got=%d", len(tc.data), attr.Length)
				}
			})
		}
	})
}

func TestAtKdfInput_Empty(t *testing.T) {
	attr := &AtKdfInput{NetworkName: ""}
	if _, err := attr.Marshal(); err == nil {
		t.Fatal("expected error for empty AT_KDF_INPUT network name")
	}

	if err := attr.Unmarshal([]byte{0x00, 0x00}); err == nil {
		t.Fatal("expected error for empty AT_KDF_INPUT network name in unmarshal")
	}
}
