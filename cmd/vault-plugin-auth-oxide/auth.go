package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/oxidecomputer/oxide.go/oxide"
)

const nonceTTL = 5 * time.Minute

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

	state := nonceState{ExpiresAt: time.Now().Add(nonceTTL)}

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
		return logical.ErrorResponse("invalid role %q", roleName), nil
	}

	nonce := d.Get("nonce").(string)

	verifier, err := b.getVerifier(ctx, req.Storage, role.Verifier)
	if err != nil {
		return nil, err
	}
	if verifier == nil {
		return nil, fmt.Errorf("got empty verifier from verifier key %q", role.Verifier)
	}

	oxideClient, err := oxide.NewClient(oxide.WithHost(verifier.Host), oxide.WithToken(verifier.Token))
	if err != nil {
		return nil, err
	}

	instanceDetails, err := b.verifyAttestation(ctx, req.Storage, oxideClient, verifier, attestation, nonce)
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

	if err := role.PopulateTokenAuth(auth, req); err != nil {
		return nil, err
	}
	auth.Renewable = false

	return &logical.Response{
		Auth: auth,
	}, nil
}

func (b *backend) verifyAttestation(ctx context.Context, storage logical.Storage, client *oxide.Client, verifier *oxideVerifier, attestation string, nonce string) (*instanceDetails, error) {
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

	if err := verifyAttestationSignature(nonce, verifier, parsed); err != nil {
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
