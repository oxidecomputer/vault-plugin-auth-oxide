package oxideauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

type deleteFailStorage struct {
	logical.Storage
	err error
}

func (s *deleteFailStorage) Delete(context.Context, string) error {
	return s.err
}

func TestVerifyNonce(t *testing.T) {
	nonce := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name           string
		setup          func(t *testing.T, storage logical.Storage) string
		wantErr        string
		wantDeleteFail bool
	}{
		{
			name: "happy",
			setup: func(t *testing.T, storage logical.Storage) string {
				require.NoError(t, writeNonce(t.Context(), storage, nonce, time.Now().Add(time.Minute)))
				return nonce
			},
			wantErr: "",
		},
		{
			name: "sad nonce not exist",
			setup: func(_ *testing.T, _ logical.Storage) string {
				return nonce
			},
			wantErr: "got empty state for nonce",
		},
		{
			name: "sad nonce not parsed",
			setup: func(_ *testing.T, _ logical.Storage) string {
				return "not-hex"
			},
			wantErr: "invalid nonce",
		},
		{
			name: "sad nonce expired",
			setup: func(t *testing.T, storage logical.Storage) string {
				require.NoError(t, writeNonce(t.Context(), storage, nonce, time.Now().Add(-time.Minute)))
				return nonce
			},
			wantErr: "expired at",
		},
		{
			name: "sad delete failed",
			setup: func(t *testing.T, storage logical.Storage) string {
				require.NoError(t, writeNonce(t.Context(), storage, nonce, time.Now().Add(time.Minute)))
				return nonce
			},
			wantErr:        "delete failed",
			wantDeleteFail: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			var storage logical.Storage = &logical.InmemStorage{}
			if tc.wantDeleteFail {
				storage = &deleteFailStorage{Storage: storage, err: errors.New("delete failed")}
			}

			config := logical.TestBackendConfig()
			config.StorageView = storage

			rawBackend, err := Factory(ctx, config)
			require.NoError(t, err)
			backend := rawBackend.(*backend)

			nonce := tc.setup(t, storage)
			err = backend.verifyNonce(ctx, storage, nonce)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}

			nonceKey := "nonce/" + nonce
			nonceValue, err := storage.Get(ctx, nonceKey)
			require.NoError(t, err)
			if tc.wantDeleteFail {
				require.NotNil(t, nonceValue)
			} else {
				require.Nil(t, nonceValue)
			}
		})
	}
}
