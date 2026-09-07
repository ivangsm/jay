package proto

// Wire protocol constants for Jay native binary protocol.

const (
	// Magic bytes: "JAY\0"
	Magic uint32 = 0x4A415900

	// Version is the protocol version. It travels in the handshake ONLY — the
	// per-frame header has no version byte — so it pins the dialect for the
	// whole connection and cannot signal a mid-connection change.
	//
	// The practical consequence, and the reason this comment is worth reading:
	// changing the layout of any Encode*/Decode* pair is invisible to the
	// handshake, so a version bump does NOT protect against wire skew. What
	// protects against it is the golden tests in wire_golden_test.go. Add a
	// field to an existing struct and they fail on purpose.
	//
	// A peer whose version is not recognised is refused rather than guessed at.
	Version byte = 0x01

	// HeaderSize is the fixed size of a request/response frame header.
	// Layout: [1B op/status] [4B stream_id] [4B meta_len] [8B data_len]
	HeaderSize = 17

	// HandshakeSize is the fixed part of the handshake.
	// Layout: [4B magic] [1B version] [1B flags] [2B auth_len]
	HandshakeSize = 8

	// HandshakeResponseSize is the server's handshake response.
	// Layout: [4B magic] [1B version] [1B status] [2B reserved]
	HandshakeResponseSize = 8

	// MaxMetaSize limits metadata payload to 1MB (prevents memory exhaustion).
	MaxMetaSize = 1 << 20

	// MaxDrainSize is how much data we'll drain on auth failure before closing.
	MaxDrainSize = 10 << 20 // 10MB
)

// Op codes for request frames.
const (
	OpCreateBucket byte = 0x01
	OpDeleteBucket byte = 0x02
	OpHeadBucket   byte = 0x03
	OpListBuckets  byte = 0x04

	OpPutObject    byte = 0x10
	OpGetObject    byte = 0x11
	OpHeadObject   byte = 0x12
	OpDeleteObject byte = 0x13
	OpListObjects  byte = 0x14

	OpCreateMultipartUpload byte = 0x20
	OpUploadPart            byte = 0x21
	OpCompleteMultipart     byte = 0x22
	OpAbortMultipart        byte = 0x23
	OpListParts             byte = 0x24

	OpPing byte = 0xFF
)

// Status codes for response frames.
const (
	StatusOK         byte = 0x00
	StatusNotFound   byte = 0x01
	StatusConflict   byte = 0x02
	StatusBadRequest byte = 0x03
	StatusForbidden  byte = 0x04
	StatusInternal   byte = 0x05
)

// Handshake status codes.
//
// Every one of these is a deliberate diagnosis, not a catch-all. The server
// used to answer HandshakeVersionMismatch for ANY handshake failure — a cut
// socket, a client that dialled the wrong port, a full server — so the one
// thing the client reported was the one thing that was almost never true.
// Adding a status is backward compatible: an older client falls through to
// its default branch and reports the raw number, which still beats a lie.
const (
	// HandshakeOK means the connection is authenticated and ready for frames.
	HandshakeOK byte = 0x00

	// HandshakeAuthFailed means the credentials were rejected, or were not
	// shaped as "token_id:secret". The two are deliberately not distinguished:
	// telling a caller that a token ID exists but its secret is wrong is a
	// probing oracle.
	HandshakeAuthFailed byte = 0x01

	// HandshakeVersionMismatch means the magic matched but the version byte is
	// one this server does not speak. It now means ONLY that.
	HandshakeVersionMismatch byte = 0x02

	// HandshakeServerBusy means the connection limit was reached. Before this
	// status existed the server closed the socket without writing anything, so
	// a client at capacity saw a bare EOF — indistinguishable from a dead
	// server or a severed network, and therefore retried the wrong way.
	HandshakeServerBusy byte = 0x03

	// HandshakeMalformed means the bytes were not a Jay handshake at all: bad
	// magic, usually something that dialled the wrong port.
	HandshakeMalformed byte = 0x04
)
