//go:build integration

package main

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFetchCert(t *testing.T) {
	for _, environment := range []string{"production", "staging"} {
		t.Run(environment, func(t *testing.T) {
			cert, err := fetchCert(environment, defaultPackageVersion)
			require.NoError(t, err)

			block, _ := pem.Decode(cert)
			require.NotNil(t, block)
			_, err = x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
		})
	}
}
