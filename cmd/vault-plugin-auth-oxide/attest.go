package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

type rawAttestation struct {
	Attest attestation `json:"Attest"`
}

func (a *rawAttestation) parse() (*parsedAttestation, error) {
	certs := make([]*x509.Certificate, len(a.Attest.CertChain))
	for idx, certBytes := range a.Attest.CertChain {
		cert, err := x509.ParseCertificate(intSliceToBytes(certBytes))
		if err != nil {
			return nil, err
		}
		certs[idx] = cert
	}

	var platformLog []byte
	var instanceLog []byte
	var conf vmInstanceConf

	for _, log := range a.Attest.MeasurementLogs {
		switch log.Rot {
		case "OxidePlatform":
			platformLog = intSliceToBytes(log.Data)
		case "OxideInstance":
			instanceLog = intSliceToBytes(log.Data)
			if err := json.Unmarshal(instanceLog, &conf); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("got unexpected rot type %q", log.Rot)
		}
	}

	return &parsedAttestation{
		signature:      intSliceToBytes(a.Attest.Attestation),
		certChain:      certs,
		platformLog:    platformLog,
		instanceLog:    instanceLog,
		vmInstanceConf: conf,
	}, nil
}

type attestation struct {
	Attestation     []int            `json:"attestation"`
	CertChain       [][]int          `json:"cert_chain"`
	MeasurementLogs []measurementLog `json:"measurement_logs"`
}

type measurementLog struct {
	Rot  string `json:"rot"`
	Data []int  `json:"data"`
}

type parsedAttestation struct {
	signature      []byte
	certChain      []*x509.Certificate
	platformLog    []byte
	instanceLog    []byte
	vmInstanceConf vmInstanceConf
}

type vmInstanceConf struct {
	Uuid    string `json:"uuid"`
	Project string `json:"project"`
	Silo    string `json:"silo"`
}

func intSliceToBytes(ints []int) []byte {
	bytes := make([]byte, len(ints))
	for idx, i := range ints {
		bytes[idx] = byte(i)
	}
	return bytes
}

func parsePlatformCert(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("failed to parse cert pem")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("expected a single cert, found trailing data %q", string(rest))
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected a block of type CERTIFICATE, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func verifyAttestationSignature(nonce string, verifier *oxideVerifier, attestation *parsedAttestation) error {
	if len(attestation.certChain) == 0 {
		return errors.New("expected at least one cert, got none")
	}
	aliasPubKey, ok := attestation.certChain[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("expected ed25519 key, got %q", attestation.certChain[0].PublicKeyAlgorithm)
	}
	for idx := 0; idx < len(attestation.certChain)-1; idx++ {
		if err := attestation.certChain[idx].CheckSignatureFrom(attestation.certChain[idx+1]); err != nil {
			return err
		}
	}

	// The final cert in the cert chain must have been signed by the platform root.
	platformIdentity, err := parsePlatformCert([]byte(verifier.PlatformIdentity))
	if err != nil {
		return err
	}
	if err := attestation.certChain[len(attestation.certChain)-1].CheckSignatureFrom(platformIdentity); err != nil {
		return err
	}

	if len(attestation.signature) != 65 {
		return fmt.Errorf("got invalid attestation signature length %d, expected 65", len(attestation.signature))
	}
	if attestation.signature[0] != 0 {
		return fmt.Errorf("got invalid attestation signature type %q, expected 0", attestation.signature[0])
	}
	signature := attestation.signature[1:]

	nonceEncoded, err := hex.DecodeString(nonce)
	if err != nil {
		return err
	}
	propolisHash := sha256.New()
	propolisHash.Write(attestation.instanceLog)
	propolisHash.Write(nonceEncoded)
	qd := propolisHash.Sum(nil)

	rotHash := sha3.New256()
	rotHash.Write(attestation.platformLog)
	rotHash.Write(qd)
	msg := rotHash.Sum(nil)

	if ok := ed25519.Verify(aliasPubKey, msg, signature); !ok {
		return fmt.Errorf("invalid attestation signature")
	}

	return nil
}
