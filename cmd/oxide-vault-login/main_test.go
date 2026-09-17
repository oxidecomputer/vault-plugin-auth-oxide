package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHelper(t *testing.T) {
	fakeVaultServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			switch r.URL.Path {
			case "/v1/auth/oxide/nonce":
				fmt.Fprint(w, `{"data":{"nonce":"abcd"}}`)
			case "/v1/auth/oxide/login":
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decoding login request: %v", err)
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}
				assert.Equal(t, map[string]string{
					"role":        "test-role",
					"nonce":       "abcd",
					"attestation": "test-attestation",
				}, body)
				fmt.Fprint(w, `{"auth":{"client_token":"test-token"}}`)
			default:
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				http.NotFound(w, r)
			}
		}),
	)
	t.Cleanup(fakeVaultServer.Close)

	config := api.NewConfig()
	config.Address = fakeVaultServer.URL
	client, err := api.NewClient(config)
	require.NoError(t, err)

	fakeAttest := func(ctx context.Context, request []byte) ([]byte, error) {
		require.JSONEq(t, `{"Attest":[171,205]}`, string(request))
		return []byte("test-attestation"), nil
	}

	token, err := helper(t.Context(), client, fakeAttest, "test-role", false)
	require.NoError(t, err)
	require.Equal(t, "test-token", token)
}
