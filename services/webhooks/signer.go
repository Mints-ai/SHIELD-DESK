package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignPayload computes legacy HMAC-SHA256 signature for outgoing webhook payload: sha256={hex}
func SignPayload(payloadBytes []byte, secretKey string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(payloadBytes)
	signatureHex := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("sha256=%s", signatureHex)
}

// VerifySignature validates customer webhook signature (legacy format)
func VerifySignature(payloadBytes []byte, signature, secretKey string) bool {
	expectedSig := SignPayload(payloadBytes, secretKey)
	return hmac.Equal([]byte(expectedSig), []byte(signature))
}

// SignTimestampedPayload computes HMAC-SHA256 signature binding timestamp and payload: t={timestamp},v1={hex}
// Formula: HMAC-SHA256(secretKey, timestamp + "." + payloadBytes)
func SignTimestampedPayload(timestamp int64, payloadBytes []byte, secretKey string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(fmt.Sprintf("%d.", timestamp)))
	mac.Write(payloadBytes)
	signatureHex := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,v1=%s", timestamp, signatureHex)
}

// VerifyTimestampedSignature validates timestamped webhook signatures with replay defense.
// If toleranceSeconds > 0, requests with timestamps older than toleranceSeconds are rejected.
func VerifyTimestampedSignature(payloadBytes []byte, signatureHeader, secretKey string, toleranceSeconds int64) bool {
	if signatureHeader == "" || secretKey == "" {
		return false
	}

	// 1. Check if signature uses timestamped format: t={ts},v1={hex}
	if strings.Contains(signatureHeader, "t=") && strings.Contains(signatureHeader, "v1=") {
		parts := strings.Split(signatureHeader, ",")
		var timestampStr, v1Signature string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "t=") {
				timestampStr = strings.TrimPrefix(part, "t=")
			} else if strings.HasPrefix(part, "v1=") {
				v1Signature = strings.TrimPrefix(part, "v1=")
			}
		}

		if timestampStr == "" || v1Signature == "" {
			return false
		}

		timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
		if err != nil {
			return false
		}

		// Replay defense: verify timestamp freshness
		if toleranceSeconds > 0 {
			now := time.Now().UTC().Unix()
			diff := now - timestamp
			if diff < 0 {
				diff = -diff // tolerate small forward clock skew
			}
			if diff > toleranceSeconds {
				return false // Expired / Replay attack
			}
		}

		// Recompute expected HMAC-SHA256
		mac := hmac.New(sha256.New, []byte(secretKey))
		mac.Write([]byte(fmt.Sprintf("%d.", timestamp)))
		mac.Write(payloadBytes)
		expectedHex := hex.EncodeToString(mac.Sum(nil))

		// Constant-time compare
		return subtle.ConstantTimeCompare([]byte(expectedHex), []byte(v1Signature)) == 1
	}

	// 2. Fallback to legacy sha256={hex} format
	return VerifySignature(payloadBytes, signatureHeader, secretKey)
}
