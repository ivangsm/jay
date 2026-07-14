package proto

func (h *connHandler) writeError(status byte, streamID uint32, message, code string) error {
	return h.writeResponseCombined(status, streamID, EncodeError(message, code))
}

// writeEncoded writes an encoded meta-only response, mapping an encoding
// failure (a field that does not fit the wire format) to an internal error
// instead of putting a corrupt frame on the wire.
func (h *connHandler) writeEncoded(status byte, streamID uint32, meta []byte, encErr error) error {
	if encErr != nil {
		h.log.Error("encode response", "err", encErr)
		return h.writeError(StatusInternal, streamID, "failed to encode response", "InternalError")
	}
	return h.writeResponseCombined(status, streamID, meta)
}

// writeResponseCombined writes a response with no data payload using a combined write.
func (h *connHandler) writeResponseCombined(status byte, streamID uint32, meta []byte) error {
	if err := h.armWriteDeadline(int64(len(meta))); err != nil {
		return err
	}
	return WriteFrameCombined(h.bw, status, streamID, meta)
}
