package meta

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
)

// formatGob is the leading byte of binary-encoded Object records. Any other
// first byte is treated as legacy JSON so bbolt records written before this
// codec existed keep decoding without a migration pass. In practice legacy
// records begin with '{' (0x7B) because they were produced by json.Marshal
// on a struct.
const formatGob byte = 0x01

// encodeObject serializes o as [formatGob][gob-encoded bytes].
//
// A fresh gob.Encoder is used on every call: gob encoders are stateful across
// a stream (they remember which types have been registered) and that state is
// useless — even harmful — when each record is stored as its own bbolt value.
// Callers must pass a non-nil pointer.
func encodeObject(o *Object) ([]byte, error) {
	if o == nil {
		return nil, errors.New("meta: nil object")
	}

	buf := bytes.Buffer{}
	if err := buf.WriteByte(formatGob); err != nil {
		return nil, fmt.Errorf("meta: write format byte: %w", err)
	}
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(o); err != nil {
		return nil, fmt.Errorf("meta: gob encode object: %w", err)
	}
	return buf.Bytes(), nil
}

// decodeObject populates *o from data. It accepts two on-disk formats:
//
//   - [formatGob][gob bytes]           — current (binary) format
//   - legacy JSON (no envelope)        — raw json.Marshal(*Object) output,
//     recognized when the first byte is '{'
//
// Any other leading byte is rejected. This is a fail-fast guard against
// corrupted or unknown-format records; we would rather surface a decode error
// than silently misinterpret bytes.
func decodeObject(data []byte, o *Object) error {
	if o == nil {
		return errors.New("meta: nil object target")
	}
	if len(data) == 0 {
		return errors.New("meta: empty object record")
	}

	switch data[0] {
	case formatGob:
		dec := gob.NewDecoder(bytes.NewReader(data[1:]))
		if err := dec.Decode(o); err != nil {
			return fmt.Errorf("meta: gob decode object: %w", err)
		}
		return nil
	case '{':
		if err := json.Unmarshal(data, o); err != nil {
			return fmt.Errorf("meta: json decode legacy object: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("meta: unknown object record format byte 0x%02x", data[0])
	}
}
