// fetch-platform-root fetches the Oxide platform root certificate from the Oxide Helios package
// repository.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	packageRepo           = "https://pkg.oxide.computer/helios/2/dev"
	packageName           = "oxide/platform-identity-cacerts"
	defaultPackageVersion = "1.0,5.11-2.0:20240719T230730Z"
)

func httpGet(client *http.Client, path string) ([]byte, error) {
	resp, err := client.Get(packageRepo + "/" + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", path, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func fetchCert(environment, version string) ([]byte, error) {
	client := &http.Client{}

	// Fetch package manifest.
	packagePath := url.QueryEscape(packageName) + "@" + url.QueryEscape(version)
	manifest, err := httpGet(client, "manifest/0/"+packagePath)
	if err != nil {
		return nil, err
	}

	// Look up platform cert in package manifest.
	expectedPath := "path=usr/share/oxide/idcerts/" + environment + ".pem"
	var matchingFiles [][]string
	for line := range strings.SplitSeq(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "file" {
			continue
		}
		for _, field := range fields[2:] {
			if field == expectedPath {
				matchingFiles = append(matchingFiles, fields)
			}
		}
	}
	if len(matchingFiles) != 1 {
		return nil, fmt.Errorf("expected exactly one file for %s", expectedPath)
	}

	// Look up content hash from manifest.
	var contentHashes []string
	for _, field := range matchingFiles[0][2:] {
		if hash, ok := strings.CutPrefix(field, "pkg.content-hash=file:sha512t_256:"); ok {
			contentHashes = append(contentHashes, hash)
		}
	}
	if len(contentHashes) != 1 {
		return nil, fmt.Errorf("expected exactly one SHA-512/256 content hash for %s", expectedPath)
	}
	expectedDigest, err := hex.DecodeString(contentHashes[0])
	if err != nil || len(expectedDigest) != sha512.Size256 {
		return nil, fmt.Errorf("invalid SHA-512/256 content hash %q", contentHashes[0])
	}

	// Fetch the certificate.
	payloadHash := matchingFiles[0][1]
	_, err = hex.DecodeString(payloadHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload hash: %w", err)
	}
	payload, err := httpGet(client, "file/1/"+payloadHash)
	if err != nil {
		return nil, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	certPEM, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// Check digest against expected.
	actualDigest := sha512.Sum512_256(certPEM)
	if !bytes.Equal(actualDigest[:], expectedDigest) {
		return nil, fmt.Errorf("certificate content hash mismatch")
	}

	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("expected a single PEM certificate")
	}
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

func main() {
	version := flag.String("version", defaultPackageVersion, "IPS package version")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-version VERSION] [production|staging]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	environment := "production"
	if flag.NArg() > 0 {
		environment = flag.Arg(0)
	}
	if flag.NArg() > 1 || (environment != "production" && environment != "staging") {
		flag.Usage()
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "Source: %s\nPackage: %s@%s\n", packageRepo, packageName, *version)
	cert, err := fetchCert(environment, *version)
	if err == nil {
		_, err = os.Stdout.Write(cert)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
