package cli

import "testing"

func TestParseLocation(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Location
		wantErr bool
	}{
		{name: "local relative", in: "./photo.webp", want: Location{Path: "./photo.webp"}},
		{name: "local absolute", in: "/tmp/photo.webp", want: Location{Path: "/tmp/photo.webp"}},
		{name: "local dash is stdin marker", in: "-", want: Location{Path: "-"}},
		{name: "bucket and key", in: "jay://images/users/1.webp", want: Location{Remote: true, Bucket: "images", Key: "users/1.webp"}},
		{name: "bucket only", in: "jay://images", want: Location{Remote: true, Bucket: "images"}},
		{name: "bucket with trailing slash", in: "jay://images/", want: Location{Remote: true, Bucket: "images"}},
		{name: "key keeps inner slashes", in: "jay://b/a/b/c", want: Location{Remote: true, Bucket: "b", Key: "a/b/c"}},
		{name: "key keeps trailing slash", in: "jay://b/prefix/", want: Location{Remote: true, Bucket: "b", Key: "prefix/"}},
		{name: "empty bucket", in: "jay://", wantErr: true},
		{name: "empty bucket with key", in: "jay:///key", wantErr: true},
		{name: "empty string", in: "", wantErr: true},
		// A path that merely mentions the scheme is not a URI.
		{name: "scheme in the middle", in: "./jay://x", want: Location{Path: "./jay://x"}},
		{name: "other scheme stays local", in: "s3://bucket/key", want: Location{Path: "s3://bucket/key"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLocation(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseLocation(%q): want error, got %+v", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLocation(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ParseLocation(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestLocationString(t *testing.T) {
	tests := []struct {
		in   Location
		want string
	}{
		{in: Location{Path: "./a.txt"}, want: "./a.txt"},
		{in: Location{Remote: true, Bucket: "b"}, want: "jay://b"},
		{in: Location{Remote: true, Bucket: "b", Key: "k"}, want: "jay://b/k"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDirPrefix(t *testing.T) {
	tests := []struct{ in, want string }{
		{in: "", want: ""},
		{in: "assets", want: "assets/"},
		{in: "assets/", want: "assets/"},
		{in: "a/b/c", want: "a/b/c/"},
	}
	for _, tt := range tests {
		if got := DirPrefix(tt.in); got != tt.want {
			t.Errorf("DirPrefix(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
