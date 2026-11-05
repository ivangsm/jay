package proto

func (h *connHandler) dispatch(req *request) error {
	switch req.op {
	case OpCreateBucket:
		return h.handleCreateBucket(req)
	case OpDeleteBucket:
		return h.handleDeleteBucket(req)
	case OpHeadBucket:
		return h.handleHeadBucket(req)
	case OpListBuckets:
		return h.handleListBuckets(req)
	case OpPutObject:
		return h.handlePutObject(req)
	case OpGetObject:
		return h.handleGetObject(req)
	case OpHeadObject:
		return h.handleHeadObject(req)
	case OpDeleteObject:
		return h.handleDeleteObject(req)
	case OpListObjects:
		return h.handleListObjects(req)
	case OpGetObjectRange:
		return h.handleGetObjectRange(req)
	case OpCopyObject:
		return h.handleCopyObject(req)
	case OpCreateMultipartUpload:
		return h.handleCreateMultipartUpload(req)
	case OpUploadPart:
		return h.handleUploadPart(req)
	case OpCompleteMultipart:
		return h.handleCompleteMultipart(req)
	case OpAbortMultipart:
		return h.handleAbortMultipart(req)
	case OpListParts:
		return h.handleListParts(req)
	case OpPing:
		return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
	default:
		// Same rule as every other refused body: drained up to MaxDrainSize,
		// answered and closed past it. A newer client probing an opcode this
		// server lacks keeps its connection; a 5 GiB body behind one does not
		// get read to be thrown away.
		if err := drainData(req); err != nil {
			return err
		}
		return h.writeError(StatusBadRequest, req.streamID, "unknown operation", "UnknownOp")
	}
}
