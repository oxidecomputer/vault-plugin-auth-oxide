package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mdlayher/vsock"
	"github.com/openbao/openbao/api/v2"
)

const attestPort = 605

func getNonce(ctx context.Context, client *api.Client) (string, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "/auth/oxide/nonce", nil)
	if err != nil {
		return "", err
	}
	nonce, ok := secret.Data["nonce"].(string)
	if !ok {
		return "", errors.New("nonce missing from response")
	}
	return nonce, nil
}

func hexToIntSlice(encoded string) ([]int, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	ints := make([]int, len(raw))
	for idx, b := range raw {
		ints[idx] = int(b)
	}
	return ints, nil
}

func getAttestation(ctx context.Context, nonce string) (string, error) {
	nonceDecoded, err := hexToIntSlice(nonce)
	if err != nil {
		return "", fmt.Errorf("decoding nonce: %w", err)
	}

	request, err := json.Marshal(struct {
		Attest []int `json:"Attest"`
	}{Attest: nonceDecoded})
	if err != nil {
		return "", fmt.Errorf("encoding attestation request: %w", err)
	}

	conn, err := vsock.Dial(vsock.Host, attestPort, nil)
	if err != nil {
		return "", fmt.Errorf("dialing vsock port: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return "", fmt.Errorf("setting attestation deadline: %w", err)
		}
	}

	if _, err := conn.Write(append(request, '\n')); err != nil {
		return "", fmt.Errorf("writing attestation request: %w", err)
	}

	bundle, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return "", fmt.Errorf("reading attestation response: %w", err)
	}

	return string(bundle), nil
}

func getToken(ctx context.Context, client *api.Client, role string, nonce string, attestation string) (string, error) {
	secret, err := client.Logical().WriteWithContext(ctx, "/auth/oxide/login", map[string]any{
		"nonce":       nonce,
		"attestation": attestation,
		"role":        role,
	})
	if err != nil {
		return "", fmt.Errorf("requesting token: %w", err)
	}
	token, err := secret.TokenID()
	if err != nil {
		return "", fmt.Errorf("retrieving token: %w", err)
	}
	return token, nil
}

func helper(ctx context.Context, client *api.Client, role string) (string, error) {
	nonce, err := getNonce(ctx, client)
	if err != nil {
		return "", fmt.Errorf("getting nonce: %w", err)
	}

	attestation, err := getAttestation(ctx, nonce)
	if err != nil {
		return "", fmt.Errorf("getting attestation: %w", err)
	}

	token, err := getToken(ctx, client, role, nonce, attestation)
	if err != nil {
		return "", fmt.Errorf("getting token: %w", err)
	}

	return token, nil
}

func main() {
	ctx := context.Background()

	role := flag.String("role", "", "oxide role")
	flag.Parse()
	if *role == "" {
		flag.Usage()
		os.Exit(2)
	}

	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		log.Fatal(err)
	}

	token, err := helper(ctx, client, *role)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(token)
}
