package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type oxideVerifier struct {
	PlatformIdentity string `json:"platform_identity"`
	Host             string `json:"host"`
	Token            string `json:"token"`
}

func (b *backend) pathVerifier() *framework.Path {
	return &framework.Path{
		Pattern: "verifier/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type: framework.TypeString,
			},
			"platform_identity": {
				Type: framework.TypeString,
			},
			"host": {
				Type: framework.TypeString,
			},
			"token": {
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathVerifierCreateUpdate,
			logical.UpdateOperation: b.pathVerifierCreateUpdate,
			logical.DeleteOperation: b.pathVerifierDelete,
			logical.ReadOperation:   b.pathVerifierRead,
		},
		ExistenceCheck: b.pathVerifierExistenceCheck,
	}
}

func (b *backend) getVerifier(ctx context.Context, s logical.Storage, name string) (*oxideVerifier, error) {
	raw, err := s.Get(ctx, "verifier/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	verifier := new(oxideVerifier)
	if err := json.Unmarshal(raw.Value, verifier); err != nil {
		return nil, err
	}
	return verifier, nil
}

func (b *backend) pathVerifierCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	verifierName := d.Get("name").(string)
	if verifierName == "" {
		return logical.ErrorResponse("must set verifier name"), nil
	}

	verifier, err := b.getVerifier(ctx, req.Storage, verifierName)
	if err != nil {
		return nil, err
	}

	if verifier == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("verifier entry not found during update operation")
		}
		verifier = new(oxideVerifier)
	}

	if platformIdentity, ok := d.GetOk("platform_identity"); ok {
		verifier.PlatformIdentity = platformIdentity.(string)
	}
	if host, ok := d.GetOk("host"); ok {
		verifier.Host = host.(string)
	}
	if token, ok := d.GetOk("token"); ok {
		verifier.Token = token.(string)
	}

	if _, err := parsePlatformCert([]byte(verifier.PlatformIdentity)); err != nil {
		return nil, fmt.Errorf("invalid platform identity cert: %w", err)
	}

	entry, err := logical.StorageEntryJSON("verifier/"+strings.ToLower(verifierName), verifier)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for verifier %s", verifierName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) pathVerifierDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	verifierName := d.Get("name").(string)
	if verifierName == "" {
		return logical.ErrorResponse("must set verifier name"), nil
	}

	if err := req.Storage.Delete(ctx, "verifier/"+strings.ToLower(verifierName)); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) pathVerifierRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	verifierName := d.Get("name").(string)
	if verifierName == "" {
		return logical.ErrorResponse("must set verifier name"), nil
	}
	verifier, err := b.getVerifier(ctx, req.Storage, verifierName)
	if err != nil {
		return nil, err
	}
	if verifier == nil {
		return nil, nil
	}
	data := map[string]any{
		"platform_identity": verifier.PlatformIdentity,
		"host":              verifier.Host,
	}
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathVerifierExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	verifier, err := b.getVerifier(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return verifier != nil, nil
}
