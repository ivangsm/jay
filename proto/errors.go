package proto

func (h *connHandler) writeError(status byte, streamID uint32, message, code string) error {
	return h.writeResponseCombined(status, streamID, EncodeError(message, code))
}

// writeResponseCombined writes a response with no data payload using a combined write.
func (h *connHandler) writeResponseCombined(status byte, streamID uint32, meta []byte) error {
	return WriteFrameCombined(h.bw, status, streamID, meta)
}
