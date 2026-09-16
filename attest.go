package oxideauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"
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

func verifyAttestationSignature(
	nonce string,
	verifier *oxideVerifier,
	attestation *parsedAttestation,
) error {
	platformIdentity, err := parsePlatformCert([]byte(verifier.PlatformIdentity))
	if err != nil {
		return err
	}
	if err := verifyAttestationCertificates(
		attestation.certChain, platformIdentity, time.Now(),
	); err != nil {
		return err
	}

	leaf := attestation.certChain[0]
	aliasPubKey, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("expected ed25519 key, got %q", leaf.PublicKeyAlgorithm)
	}

	if len(attestation.signature) != 65 {
		return fmt.Errorf(
			"got invalid attestation signature length %d, expected 65",
			len(attestation.signature),
		)
	}
	if attestation.signature[0] != 0 {
		return fmt.Errorf(
			"got invalid attestation signature type %q, expected 0",
			attestation.signature[0],
		)
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

var diceTCBInfoOID = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

// verifyAttestationCertificates verifies the certificate chain, from the leaf to the intermediates
// (both provided via the attestation bundle), to the manufacturing certificate, configured in the
// `verifier`.
func verifyAttestationCertificates(
	chain []*x509.Certificate,
	root *x509.Certificate,
	now time.Time,
) error {
	if len(chain) == 0 {
		return errors.New("expected at least one cert, got none")
	}
	leaf, _ := extractTCBInfo(chain[0])

	roots := x509.NewCertPool()
	root, _ = extractTCBInfo(root)
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		cert, _ = extractTCBInfo(cert)
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	if err != nil {
		return fmt.Errorf("verifying attestation certificate chain: %w", err)
	}
	return nil
}

// extractTCBInfo extracts the DICE TCB extension from the certificate. We return a clone of the
// original certificate with the `UnhandledCriticalExtension` removed, so that subsequent calls to
// `Verify` succeed, as well as the extracted TCB info.
//
//nolint:unparam
func extractTCBInfo(cert *x509.Certificate) (*x509.Certificate, []byte) {
	var tcbInfo []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(diceTCBInfoOID) {
			tcbInfo = ext.Value
			break
		}
	}
	clone := *cert
	clone.UnhandledCriticalExtensions = slices.DeleteFunc(
		slices.Clone(cert.UnhandledCriticalExtensions),
		func(oid asn1.ObjectIdentifier) bool {
			return oid.Equal(diceTCBInfoOID)
		},
	)
	return &clone, tcbInfo
}
