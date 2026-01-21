package rpc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// RequestSigner handles signing and verification of RPC requests
type RequestSigner struct {
	secretKey []byte
}

// NewRequestSigner creates a new request signer with the given secret key
func NewRequestSigner(secretKey []byte) *RequestSigner {
	return &RequestSigner{
		secretKey: secretKey,
	}
}

// SignRequest generates an HMAC signature for a request
// The signature covers: operation + args + timestamp + actor
func (rs *RequestSigner) SignRequest(req *Request, timestamp time.Time) string {
	// Create payload to sign
	payload := fmt.Sprintf("%s|%s|%d|%s|%s",
		req.Operation,
		string(req.Args),
		timestamp.Unix(),
		req.Actor,
		req.Cwd,
	)

	h := hmac.New(sha256.New, rs.secretKey)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyRequest verifies the HMAC signature of a request
// Returns nil if signature is valid, error otherwise
func (rs *RequestSigner) VerifyRequest(req *Request, timestamp time.Time, signature string) error {
	expectedSignature := rs.SignRequest(req, timestamp)

	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("invalid request signature")
	}

	return nil
}

// SignResponse generates an HMAC signature for a response
func (rs *RequestSigner) SignResponse(resp *Response, timestamp time.Time) string {
	payload := fmt.Sprintf("%v|%s|%d",
		resp.Success,
		resp.Error,
		timestamp.Unix(),
	)

	h := hmac.New(sha256.New, rs.secretKey)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyResponse verifies the HMAC signature of a response
func (rs *RequestSigner) VerifyResponse(resp *Response, timestamp time.Time, signature string) error {
	expectedSignature := rs.SignResponse(resp, timestamp)

	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("invalid response signature")
	}

	return nil
}

// timestampString returns a formatted timestamp for signatures
func timestampString(t time.Time) string {
	return fmt.Sprintf("%d", t.UnixNano())
}
