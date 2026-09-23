package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SignPayload computes HMAC-SHA256 signature for outgoing webhook payload: sha256={hex}
func SignPayload(payloadBytes []byte, secretKey string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(payloadBytes)
	signatureHex := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("sha256=%s", signatureHex)
}

// VerifySignature validates customer webhook signature
func VerifySignature(payloadBytes []byte, signature, secretKey string) bool {
	expectedSig := SignPayload(payloadBytes, secretKey)
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}
