package cli

import "testing"

func TestNormalizeAddr(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "", want: defaultNativeAddr},
		{in: "   ", want: defaultNativeAddr},
		{in: ":4444", want: "localhost:4444"},
		{in: ":4012", want: "localhost:4012"},
		{in: "jay.internal:4444", want: "jay.internal:4444"},
		{in: "10.0.0.5:4012", want: "10.0.0.5:4012"},
	}
	for _, tt := range tests {
		if got := normalizeAddr(tt.in); got != tt.want {
			t.Errorf("normalizeAddr(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDialWithoutCredentialsFails(t *testing.T) {
	// Refusing here is the point: an anonymous fallback would make every
	// later command fail with a confusing permission error instead.
	if _, err := (Options{Addr: "localhost:1"}).dial(); err == nil {
		t.Fatal("dial without credentials: want error, got nil")
	}
	if _, err := (Options{Addr: "localhost:1", TokenID: "id"}).dial(); err == nil {
		t.Fatal("dial with only a token ID: want error, got nil")
	}
}
