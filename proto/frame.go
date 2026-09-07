package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// WriteHeader writes the 17-byte frame header to w.
func WriteHeader(w io.Writer, opOrStatus byte, streamID uint32, metaLen uint32, dataLen int64) error {
	if dataLen < 0 {
		return errors.New("invalid negative data length")
	}
	var buf [HeaderSize]byte
	buf[0] = opOrStatus
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint32(buf[5:9], metaLen)
	binary.BigEndian.PutUint64(buf[9:17], uint64(dataLen))
	_, err := w.Write(buf[:])
	return err
}

// ReadHeader reads the 17-byte frame header from r.
func ReadHeader(r io.Reader) (opOrStatus byte, streamID uint32, metaLen uint32, dataLen int64, err error) {
	var buf [HeaderSize]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("read header: %w", err)
	}
	opOrStatus = buf[0]
	streamID = binary.BigEndian.Uint32(buf[1:5])
	metaLen = binary.BigEndian.Uint32(buf[5:9])
	dataLen = int64(binary.BigEndian.Uint64(buf[9:17]))
	if dataLen < 0 {
		return 0, 0, 0, 0, errors.New("invalid negative data length")
	}
	return opOrStatus, streamID, metaLen, dataLen, nil
}

// WriteHandshake writes the client handshake to w.
func WriteHandshake(w io.Writer, credentials string) error {
	creds := []byte(credentials)
	var buf [HandshakeSize]byte
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	buf[4] = Version
	buf[5] = 0x00 // flags
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(creds)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	_, err := w.Write(creds)
	return err
}

// Handshake failure sentinels. The server maps these onto the Handshake*
// status bytes; without them every failure looked the same and got answered
// as a version mismatch. Callers should match with errors.Is, never on the
// message text.
var (
	// ErrHandshakeMagic means the first four bytes are not "JAY\0" — whatever
	// connected is not speaking this protocol.
	ErrHandshakeMagic = errors.New("proto: invalid handshake magic")

	// ErrHandshakeVersion means the magic matched but the version byte did not.
	ErrHandshakeVersion = errors.New("proto: unsupported protocol version")

	// ErrHandshakeCredentials means the credential field is absent or unusable.
	ErrHandshakeCredentials = errors.New("proto: malformed handshake credentials")
)

// ReadHandshake reads and validates the client handshake from r.
// Returns the credentials string (token_id:secret).
//
// The returned error is one of ErrHandshakeMagic, ErrHandshakeVersion or
// ErrHandshakeCredentials for a well-formed peer that disagrees with us, or a
// wrapped I/O error when the socket died mid-handshake. The server needs that
// distinction to answer with a status that is true.
func ReadHandshake(r io.Reader) (credentials string, err error) {
	var buf [HandshakeSize]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return "", fmt.Errorf("read handshake: %w", err)
	}
	magic := binary.BigEndian.Uint32(buf[0:4])
	if magic != Magic {
		return "", fmt.Errorf("%w: 0x%08X", ErrHandshakeMagic, magic)
	}
	version := buf[4]
	if version != Version {
		return "", fmt.Errorf("%w: %d", ErrHandshakeVersion, version)
	}
	authLen := binary.BigEndian.Uint16(buf[6:8])
	if authLen == 0 {
		return "", fmt.Errorf("%w: empty", ErrHandshakeCredentials)
	}
	authBuf := make([]byte, authLen)
	if _, err = io.ReadFull(r, authBuf); err != nil {
		return "", fmt.Errorf("read credentials: %w", err)
	}
	return string(authBuf), nil
}

// WriteHandshakeResponse writes the server handshake response.
func WriteHandshakeResponse(w io.Writer, status byte) error {
	var buf [HandshakeResponseSize]byte
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	buf[4] = Version
	buf[5] = status
	// buf[6:8] reserved = 0
	_, err := w.Write(buf[:])
	return err
}

// ReadHandshakeResponse reads the server's handshake response.
func ReadHandshakeResponse(r io.Reader) (status byte, err error) {
	var buf [HandshakeResponseSize]byte
	if _, err = io.ReadFull(r, buf[:]); err != nil {
		return 0, fmt.Errorf("read handshake response: %w", err)
	}
	magic := binary.BigEndian.Uint32(buf[0:4])
	if magic != Magic {
		return 0, fmt.Errorf("invalid magic: 0x%08X", magic)
	}
	return buf[5], nil
}

// WriteFrame writes a complete frame (header + metadata + data).
// If data is nil, dataLen must be 0.
func WriteFrame(w io.Writer, opOrStatus byte, streamID uint32, meta []byte, data io.Reader, dataLen int64) error {
	if err := WriteHeader(w, opOrStatus, streamID, uint32(len(meta)), dataLen); err != nil {
		return err
	}
	if len(meta) > 0 {
		if _, err := w.Write(meta); err != nil {
			return err
		}
	}
	if dataLen > 0 && data != nil {
		if _, err := io.CopyN(w, data, dataLen); err != nil {
			return err
		}
	}
	return nil
}
