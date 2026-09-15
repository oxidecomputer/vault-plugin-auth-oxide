package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestVerifyAttestation(t *testing.T) {
	// Load a real nonce, attestation, and platform certificate from fixtures. We'll perturb the
	// valid fixtures in various ways to prove that verification fails on invalid data.
	platformIdentity, err := os.ReadFile("testdata/platform-identity.pem")
	require.NoError(t, err)

	nonceBytes, err := os.ReadFile("testdata/nonce.txt")
	require.NoError(t, err)

	attestationBytes, err := os.ReadFile("testdata/attestation.json")
	require.NoError(t, err)

	verifier := oxideVerifier{
		PlatformIdentity: string(platformIdentity),
	}
	nonce := strings.TrimSpace(string(nonceBytes))
	attestation := string(attestationBytes)

	var raw rawAttestation
	require.NoError(t, json.Unmarshal([]byte(attestation), &raw))

	parsed, err := raw.parse()
	require.NoError(t, err)

	attestationBadChain := *parsed
	attestationBadChain.certChain = slices.Delete(
		slices.Clone(parsed.certChain), 1, 2,
	)

	attestationBadSignature := *parsed
	attestationBadSignature.signature = bytes.Clone(parsed.signature)
	attestationBadSignature.signature[1] ^= 1

	attestationBadPlatformLog := *parsed
	attestationBadPlatformLog.platformLog = bytes.Clone(parsed.platformLog)
	attestationBadPlatformLog.platformLog[0] ^= 1

	badNonce := []byte(nonce)
	if badNonce[0] == '0' {
		badNonce[0] = '1'
	} else {
		badNonce[0] = '0'
	}

	badVerifier := oxideVerifier{
		PlatformIdentity: string(makePlatformCert(t)),
	}

	for _, tc := range []struct {
		name        string
		attestation *parsedAttestation
		nonce       string
		verifier    oxideVerifier
		wantErr     string
	}{
		{
			name:        "happy",
			nonce:       nonce,
			attestation: parsed,
			verifier:    verifier,
			wantErr:     "",
		},
		{
			name:        "sad bad chain",
			attestation: &attestationBadChain,
			nonce:       nonce,
			verifier:    verifier,
			wantErr:     "Ed25519 verification failure",
		},
		{
			name:        "sad bad signature",
			attestation: &attestationBadSignature,
			nonce:       nonce,
			verifier:    verifier,
			wantErr:     "invalid attestation signature",
		},
		{
			name:        "sad bad nonce",
			attestation: parsed,
			nonce:       string(badNonce),
			verifier:    verifier,
			wantErr:     "invalid attestation signature",
		},
		{
			name:        "sad bad platform log",
			attestation: &attestationBadPlatformLog,
			nonce:       nonce,
			verifier:    verifier,
			wantErr:     "invalid attestation signature",
		},
		{
			name:        "sad bad platform cert",
			attestation: parsed,
			nonce:       nonce,
			verifier:    badVerifier,
			wantErr:     "ECDSA verification failure",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyAttestationSignature(tc.nonce, &tc.verifier, tc.attestation)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

func makePlatformCert(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test platform root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &key.PublicKey, key,
	)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))
}
