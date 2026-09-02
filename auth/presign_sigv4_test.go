package auth

// The expectations in this file are AWS's own published numbers, transcribed
// from the Signature Version 4 documentation. They are not recorded from jay:
// a test that asserts what the implementation happens to produce would go green
// on a wrong canonical request just as happily as on a right one.
//
// Two vectors, both from AWS:
//
//   - The signing-key derivation example (service "iam", 20150830), which pins
//     the four-round HMAC chain independently of anything S3-shaped.
//   - The S3 presigned-URL example (GET /test.txt on examplebucket,
//     20130524T000000Z), which pins the canonical request, the string to sign
//     and the final signature of the query-string form end to end.

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// AWS's published signing-key derivation example.
const (
	awsExampleSigningSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	awsExampleSigningKeyHex = "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
)

// AWS's published S3 presigned-URL example.
const (
	awsPresignAccessKey = "AKIAIOSFODNN7EXAMPLE"
	awsPresignSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsPresignHost      = "examplebucket.s3.amazonaws.com"
	awsPresignAmzDate   = "20130524T000000Z"
	awsPresignDateStamp = "20130524"
	awsPresignRegion    = "us-east-1"

	awsPresignCanonicalQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z" +
		"&X-Amz-Expires=86400" +
		"&X-Amz-SignedHeaders=host"

	awsPresignCanonicalRequest = "GET\n" +
		"/test.txt\n" +
		awsPresignCanonicalQuery + "\n" +
		"host:examplebucket.s3.amazonaws.com\n" +
		"\n" +
		"host\n" +
		"UNSIGNED-PAYLOAD"

	awsPresignStringToSign = "AWS4-HMAC-SHA256\n" +
		"20130524T000000Z\n" +
		"20130524/us-east-1/s3/aws4_request\n" +
		"3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04"

	awsPresignSignature = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
)

func TestDeriveSigningKey_MatchesAWSPublishedVector(t *testing.T) {
	got := hex.EncodeToString(deriveSigningKey(awsExampleSigningSecret, "20150830", "us-east-1", "iam"))
	if got != awsExampleSigningKeyHex {
		t.Fatalf("signing key\n got %s\nwant %s", got, awsExampleSigningKeyHex)
	}
}

func TestBuildCanonicalRequest_MatchesAWSPresignedVector(t *testing.T) {
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: "/test.txt", RawQuery: awsPresignCanonicalQuery},
		Host:   awsPresignHost,
		Header: make(http.Header),
	}

	got := buildCanonicalRequestFrom(req, "host", awsPresignCanonicalQuery, unsignedPayload)
	if got != awsPresignCanonicalRequest {
		t.Fatalf("canonical request\n got %q\nwant %q", got, awsPresignCanonicalRequest)
	}

	sts := buildStringToSign(awsPresignDateStamp, awsPresignAmzDate, awsPresignRegion, got)
	if sts != awsPresignStringToSign {
		t.Fatalf("string to sign\n got %q\nwant %q", sts, awsPresignStringToSign)
	}

	key := deriveSigningKey(awsPresignSecret, awsPresignDateStamp, awsPresignRegion, sigV4Service)
	sig := hex.EncodeToString(hmacSHA256(key, []byte(sts)))
	if sig != awsPresignSignature {
		t.Fatalf("signature\n got %s\nwant %s", sig, awsPresignSignature)
	}
}

func TestPresignQuery_MatchesAWSPresignedVector(t *testing.T) {
	got, err := PresignQuery(PresignInput{
		AccessKeyID: awsPresignAccessKey,
		SecretKey:   awsPresignSecret,
		Region:      awsPresignRegion,
		Method:      http.MethodGet,
		Host:        awsPresignHost,
		Path:        "/test.txt",
		Expires:     24 * time.Hour,
		Now:         time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("PresignQuery: %v", err)
	}

	want := awsPresignCanonicalQuery + "&X-Amz-Signature=" + awsPresignSignature
	if got != want {
		t.Fatalf("presigned query\n got %s\nwant %s", got, want)
	}
}

func TestPresignQuery_RefusesToMintWhatCannotVerify(t *testing.T) {
	base := PresignInput{
		AccessKeyID: "tok",
		SecretKey:   "sec",
		Region:      "us-east-1",
		Method:      http.MethodGet,
		Host:        "jay.test",
		Path:        "/b/k",
		Expires:     time.Hour,
	}

	cases := map[string]func(*PresignInput){
		"no access key":     func(in *PresignInput) { in.AccessKeyID = "" },
		"no secret":         func(in *PresignInput) { in.SecretKey = "" },
		"no region":         func(in *PresignInput) { in.Region = "" },
		"no method":         func(in *PresignInput) { in.Method = "" },
		"no host":           func(in *PresignInput) { in.Host = "" },
		"relative path":     func(in *PresignInput) { in.Path = "b/k" },
		"zero expiry":       func(in *PresignInput) { in.Expires = 0 },
		"negative expiry":   func(in *PresignInput) { in.Expires = -time.Second },
		"expiry over 7days": func(in *PresignInput) { in.Expires = MaxPresignExpiry + time.Second },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base
			mutate(&in)
			got, err := PresignQuery(in)
			if err == nil {
				t.Fatalf("want error, got URL %q", got)
			}
			if got != "" {
				t.Fatalf("a rejected presign must not return a query, got %q", got)
			}
		})
	}
}

func TestStripSignatureParam(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"X-Amz-Signature=abc", ""},
		{"a=1&X-Amz-Signature=abc&b=2", "a=1&b=2"},
		// Case-insensitive: a signer that spelled it differently still gets its
		// own parameter excluded, exactly as it excluded it when signing.
		{"a=1&x-amz-signature=abc", "a=1"},
		// Everything else survives byte for byte, encoding included.
		{"prefix=a%2Fb&X-Amz-Signature=z", "prefix=a%2Fb"},
	}
	for _, c := range cases {
		if got := stripSignatureParam(c.in); got != c.want {
			t.Fatalf("stripSignatureParam(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractPresignParams_RejectsDuplicates(t *testing.T) {
	q := url.Values{}
	q.Set("X-Amz-Algorithm", sigV4Algorithm)
	q.Set("X-Amz-Credential", "k/20260101/us-east-1/s3/aws4_request")
	q.Set("X-Amz-Date", "20260101T000000Z")
	q.Set("X-Amz-SignedHeaders", "host")
	q.Set("X-Amz-Signature", "deadbeef")
	q["X-Amz-Expires"] = []string{"60"}
	q["x-amz-expires"] = []string{"604800"}

	if _, err := extractPresignParams(q); err == nil {
		t.Fatal("two spellings of X-Amz-Expires must be refused, not resolved by guessing")
	}
}

func TestParsePresignCredential(t *testing.T) {
	if _, _, _, err := parsePresignCredential("k/20260101/us-east-1/s3/aws4_request"); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}
	bad := []string{
		"k/20260101/us-east-1/s3",
		"k/20260101/us-east-1/iam/aws4_request",
		"k/20260101/us-east-1/s3/aws4_req",
		"//us-east-1/s3/aws4_request",
		"k/20260101//s3/aws4_request",
		"",
	}
	for _, c := range bad {
		if _, _, _, err := parsePresignCredential(c); err == nil {
			t.Fatalf("credential %q should have been rejected", c)
		}
	}
}

func TestCheckPresignWindow(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	signedAt := now.Add(-time.Minute)

	if err := checkPresignWindow(signedAt, "3600", now); err != nil {
		t.Fatalf("URL inside its window rejected: %v", err)
	}
	if err := checkPresignWindow(now.Add(-2*time.Hour), "3600", now); err == nil {
		t.Fatal("expired URL accepted")
	}
	if err := checkPresignWindow(now.Add(time.Hour), "3600", now); err == nil {
		t.Fatal("URL dated an hour in the future accepted")
	}
	// Inside the tolerated skew: a client clock a few minutes fast is not an
	// attack, and rejecting it would make jay unusable behind a bad NTP.
	if err := checkPresignWindow(now.Add(5*time.Minute), "3600", now); err != nil {
		t.Fatalf("URL within clock skew rejected: %v", err)
	}
	overCeiling := strings.TrimSpace("604801")
	if err := checkPresignWindow(signedAt, overCeiling, now); err == nil {
		t.Fatal("X-Amz-Expires above the 7-day ceiling accepted")
	}
	for _, bad := range []string{"", "0", "-1", "abc", "3600.5"} {
		if err := checkPresignWindow(signedAt, bad, now); err == nil {
			t.Fatalf("X-Amz-Expires %q accepted", bad)
		}
	}
}
