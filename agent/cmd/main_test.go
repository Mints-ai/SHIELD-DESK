package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
)

func generateTestRSAKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey, string) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test RSA key pair: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return privKey, &privKey.PublicKey, string(pubKeyPEM)
}

func signCanonicalPayload(t *testing.T, privKey *rsa.PrivateKey, agentID, command, nonce, tier string) string {
	t.Helper()
	canonical := fmt.Sprintf("%s|%s|%s|%s", agentID, command, nonce, tier)
	digest := sha256.Sum256([]byte(canonical))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("Failed to sign payload: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sigBytes)
}

func TestVerifyCommandSignature_Valid(t *testing.T) {
	privKey, pubKey, _ := generateTestRSAKeyPair(t)

	agentID := "ea111111-1111-1111-1111-111111111111"
	command := "isolate_host 10.0.0.0/24"
	nonce := "test-nonce-12345"
	tier := "Tier 2"

	signature := signCanonicalPayload(t, privKey, agentID, command, nonce, tier)

	err := verifyCommandSignature(pubKey, agentID, command, nonce, tier, signature)
	if err != nil {
		t.Fatalf("Expected valid signature to verify successfully, got: %v", err)
	}
}

func TestVerifyCommandSignature_TamperedCommand(t *testing.T) {
	privKey, pubKey, _ := generateTestRSAKeyPair(t)

	agentID := "ea111111-1111-1111-1111-111111111111"
	command := "isolate_host 10.0.0.0/24"
	nonce := "test-nonce-12345"
	tier := "Tier 2"

	signature := signCanonicalPayload(t, privKey, agentID, command, nonce, tier)

	// Attacker tampers with command to wipe disk or kill process
	tamperedCommand := "kill_process 1"
	err := verifyCommandSignature(pubKey, agentID, tamperedCommand, nonce, tier, signature)
	if err == nil {
		t.Fatal("Expected tampered command to fail verification, but verification succeeded!")
	}
}

func TestVerifyCommandSignature_TamperedAgentID(t *testing.T) {
	privKey, pubKey, _ := generateTestRSAKeyPair(t)

	agentID := "ea111111-1111-1111-1111-111111111111"
	command := "isolate_host"
	nonce := "test-nonce-12345"
	tier := "Tier 2"

	signature := signCanonicalPayload(t, privKey, agentID, command, nonce, tier)

	// Attacker replays command targeted at another agent
	tamperedAgentID := "ea222222-2222-2222-2222-222222222222"
	err := verifyCommandSignature(pubKey, tamperedAgentID, command, nonce, tier, signature)
	if err == nil {
		t.Fatal("Expected cross-agent replayed command to fail verification!")
	}
}

func TestVerifyCommandSignature_MissingOrForgedSignature(t *testing.T) {
	_, pubKey, _ := generateTestRSAKeyPair(t)

	agentID := "ea111111-1111-1111-1111-111111111111"
	command := "isolate_host"
	nonce := "test-nonce-12345"
	tier := "Tier 2"

	// 1. Missing signature
	err := verifyCommandSignature(pubKey, agentID, command, nonce, tier, "")
	if err == nil {
		t.Fatal("Expected empty signature to fail verification")
	}

	// 2. Forged signature
	forgedSig := base64.StdEncoding.EncodeToString([]byte("forged-signature-bytes"))
	err = verifyCommandSignature(pubKey, agentID, command, nonce, tier, forgedSig)
	if err == nil {
		t.Fatal("Expected forged signature to fail verification")
	}
}

func TestParseRSAPublicKeyPEM(t *testing.T) {
	_, _, pemStr := generateTestRSAKeyPair(t)

	pubKey, err := parseRSAPublicKeyPEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("Failed to parse valid PEM string: %v", err)
	}
	if pubKey == nil {
		t.Fatal("Expected non-nil public key")
	}

	// Invalid PEM
	_, err = parseRSAPublicKeyPEM([]byte("INVALID PEM CONTENT"))
	if err == nil {
		t.Fatal("Expected error on invalid PEM")
	}
}
