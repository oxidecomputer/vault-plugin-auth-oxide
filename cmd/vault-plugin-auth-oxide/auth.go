package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/oxidecomputer/oxide.go/oxide"
)

type nonceState struct {
	ExpiresAt time.Time `json:"expires_at"`
}

func (b *backend) pathAuthNonce() *framework.Path {
	return &framework.Path{
		Pattern: "nonce",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleAuthNonce,
		},
	}
}

func (b *backend) pathAuthLogin() *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"attestation": {
				Type: framework.TypeString,
			},
			"role": {
				Type: framework.TypeString,
			},
			"nonce": {
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleAuthLogin,
		},
	}
}

func (b *backend) handleAuthNonce(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var nonce [32]byte
	rand.Read(nonce[:])
	encoded := hex.EncodeToString(nonce[:])

	state := nonceState{ExpiresAt: time.Now().Add(time.Minute)}

	entry, err := logical.StorageEntryJSON("nonce/"+encoded, state)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for nonce %s", encoded)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"nonce": encoded,
		},
	}, nil
}

func (b *backend) handleAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	attestation := d.Get("attestation").(string)

	roleName := d.Get("role").(string)
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, logical.ErrInvalidCredentials
	}

	nonce := d.Get("nonce").(string)

	config, err := b.getConfig(ctx, req.Storage, role.Config)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("got empty config from config key %q", role.Config)
	}

	oxideClient, err := oxide.NewClient(oxide.WithHost(config.Host), oxide.WithToken(config.Token))
	if err != nil {
		return nil, err
	}

	instanceDetails, err := b.verifyAttestation(ctx, req.Storage, oxideClient, config, attestation, nonce)
	if err != nil {
		b.Logger().Warn("error verifying attestation", "role", role, "error", err)
		return nil, logical.ErrInvalidCredentials
	}

	if err := role.authorize(instanceDetails); err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"instanceID":   instanceDetails.InstanceID,
		"projectID":    instanceDetails.ProjectID,
		"instanceName": instanceDetails.InstanceName,
		"projectName":  instanceDetails.ProjectName,
	}
	auth := &logical.Auth{
		DisplayName: instanceDetails.InstanceID,
		Alias: &logical.Alias{
			Name:     instanceDetails.InstanceID,
			Metadata: metadata,
		},
		Metadata: metadata,
		InternalData: map[string]any{
			"role": roleName,
		},
	}

	role.PopulateTokenAuth(auth)
	auth.Renewable = false

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) verifyAttestation(ctx context.Context, storage logical.Storage, client *oxide.Client, config *oxideConfig, attestation string, nonce string) (*instanceDetails, error) {
	var raw rawAttestation
	if err := json.Unmarshal([]byte(attestation), &raw); err != nil {
		return nil, err
	}
	parsed, err := raw.parse()
	if err != nil {
		return nil, err
	}

	if err := b.verifyNonce(ctx, storage, nonce); err != nil {
		return nil, err
	}

	if err := verifyAttestationSignature(nonce, config, parsed); err != nil {
		return nil, err
	}

	instance, err := client.InstanceView(ctx, oxide.InstanceViewParams{
		Instance: oxide.NameOrId(parsed.vmInstanceConf.Uuid),
	})
	if err != nil {
		return nil, err
	}
	if instance.ProjectId != parsed.vmInstanceConf.Project {
		return nil, fmt.Errorf("expected project id %q, got %q", parsed.vmInstanceConf.Project, instance.ProjectId)
	}

	project, err := client.ProjectView(ctx, oxide.ProjectViewParams{
		Project: oxide.NameOrId(instance.ProjectId),
	})
	if err != nil {
		return nil, err
	}

	return &instanceDetails{
		ProjectID:    instance.ProjectId,
		InstanceID:   instance.Id,
		ProjectName:  string(project.Name),
		InstanceName: string(instance.Name),
	}, nil
}

// verifyNonce checks that the nonce is valid and not expired, then deletes it from storage.
func (b *backend) verifyNonce(ctx context.Context, storage logical.Storage, nonce string) error {
	if _, err := hex.DecodeString(nonce); err != nil {
		return fmt.Errorf("invalid nonce %q", nonce)
	}

	// Lock using a striped lock so that multiple callers can't consume the same nonce.
	lock := locksutil.LockForKey(b.locks, nonce)
	lock.Lock()
	defer lock.Unlock()

	nonceKey := "nonce/" + nonce
	raw, err := storage.Get(ctx, nonceKey)
	if err != nil {
		return err
	}
	if raw == nil {
		return fmt.Errorf("got empty state for nonce %q", nonce)
	}

	var state nonceState
	if err := json.Unmarshal(raw.Value, &state); err != nil {
		return err
	}
	if time.Now().After(state.ExpiresAt) {
		return fmt.Errorf("nonce %q expired at %q", nonce, state.ExpiresAt)
	}
	if err := storage.Delete(ctx, nonceKey); err != nil {
		return err
	}

	return nil
}

type instanceDetails struct {
	InstanceID string
	ProjectID  string

	InstanceName string
	ProjectName  string
}
