package proto

import "encoding/json"

// errorResponse is the JSON payload for error responses.
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func marshalError(message, code string) []byte {
	b, _ := json.Marshal(errorResponse{Error: message, Code: code})
	return b
}

func (h *connHandler) writeError(status byte, streamID uint32, message, code string) error {
	return h.writeResponse(status, streamID, marshalError(message, code), nil, 0)
}
