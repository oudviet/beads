package rpc

import (
	"encoding/json"
	"fmt"
)

const (
	// MaxRequestSize is the maximum allowed size for a request payload (10MB)
	// This prevents DoS attacks via large payloads
	MaxRequestSize = 10 * 1024 * 1024

	// MaxResponseSize is the maximum allowed size for a response payload (50MB)
	// Responses can be larger (e.g., list operations with many issues)
	MaxResponseSize = 50 * 1024 * 1024
)

// ValidateRequestSize checks if a request's payload size is within limits
func ValidateRequestSize(req *Request) error {
	// Check the raw JSON size of args
	argsSize := len(req.Args)
	if argsSize > MaxRequestSize {
		return fmt.Errorf("request payload too large: %d bytes (max %d bytes)", argsSize, MaxRequestSize)
	}

	// Estimate total request size (rough estimate)
	totalSize := argsSize + len(req.Operation) + len(req.Actor) + len(req.Cwd) + len(req.ExpectedDB)
	if totalSize > MaxRequestSize {
		return fmt.Errorf("request too large: estimated %d bytes (max %d bytes)", totalSize, MaxRequestSize)
	}

	return nil
}

// ValidateResponseSize checks if a response's payload size is within limits
func ValidateResponseSize(resp *Response) error {
 dataSize := len(resp.Data)
	if dataSize > MaxResponseSize {
		return fmt.Errorf("response payload too large: %d bytes (max %d bytes)", dataSize, MaxResponseSize)
	}

	return nil
}

// EstimateRequestSize estimates the total size of a request when marshaled to JSON
// This is a rough estimate to catch obviously oversized requests early
func EstimateRequestSize(req *Request) int {
	// Base size for JSON structure overhead
	baseSize := 100

	// Size of each field
	baseSize += len(req.Operation)
	baseSize += len(req.Args)
	baseSize += len(req.Actor)
	baseSize += len(req.RequestID)
	baseSize += len(req.Cwd)
	baseSize += len(req.ExpectedDB)
	baseSize += len(req.AuthToken)
	baseSize += len(req.Signature)

	return baseSize
}

// SafeMarshal marshals data to JSON with size limit checking
// Returns error if the marshaled data exceeds MaxRequestSize
func SafeMarshal(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	if len(data) > MaxRequestSize {
		return nil, fmt.Errorf("data too large to marshal: %d bytes (max %d bytes)", len(data), MaxRequestSize)
	}

	return data, nil
}
