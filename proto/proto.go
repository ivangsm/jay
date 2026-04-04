package proto

// Wire protocol constants for Jay native binary protocol.

const (
	// Magic bytes: "JAY\0"
	Magic uint32 = 0x4A415900

	// Protocol version
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

	// MaxMetaSize limits metadata payload to 16MB (prevents memory exhaustion).
	MaxMetaSize = 16 << 20

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
	OpUploadPart           byte = 0x21
	OpCompleteMultipart    byte = 0x22
	OpAbortMultipart       byte = 0x23
	OpListParts            byte = 0x24

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
const (
	HandshakeOK              byte = 0x00
	HandshakeAuthFailed      byte = 0x01
	HandshakeVersionMismatch byte = 0x02
)
