package oxideauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/oxidecomputer/oxide.go/oxide"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
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

func TestGetInstanceDetails(t *testing.T) {
	ctrl := gomock.NewController(t)
	oxideClient := NewMockOxideClient(ctrl)

	instanceID := "10000000-0000-0000-0000-000000000001"
	projectID := "10000000-0000-0000-0000-000000000002"
	instanceName := "test-instance"
	projectName := "test-project"

	oxideClient.EXPECT().InstanceView(gomock.Any(), oxide.InstanceViewParams{
		Instance: oxide.NameOrId(instanceID),
	}).Return(&oxide.Instance{
		Id:        instanceID,
		Name:      oxide.Name(instanceName),
		ProjectId: projectID,
	}, nil)
	oxideClient.EXPECT().ProjectView(gomock.Any(), oxide.ProjectViewParams{
		Project: oxide.NameOrId(projectID),
	}).Return(&oxide.Project{
		Id:   projectID,
		Name: oxide.Name(projectName),
	}, nil)

	details, err := getInstanceDetails(context.Background(), oxideClient, instanceID)
	require.NoError(t, err)
	require.Equal(t, &instanceDetails{
		InstanceID:   instanceID,
		ProjectID:    projectID,
		InstanceName: instanceName,
		ProjectName:  projectName,
	}, details)
}
