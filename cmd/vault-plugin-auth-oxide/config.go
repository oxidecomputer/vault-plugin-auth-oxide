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

type oxideConfig struct {
	PlatformIdentity string `json:"platform_identity"`
	Host             string `json:"host"`
	Token            string `json:"token"`
}

func (b *backend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config/" + framework.GenericNameRegex("name"),
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
			logical.CreateOperation: b.pathConfigCreateUpdate,
			logical.UpdateOperation: b.pathConfigCreateUpdate,
			logical.DeleteOperation: b.pathConfigDelete,
			logical.ReadOperation:   b.pathConfigRead,
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
	}
}

func (b *backend) getConfig(ctx context.Context, s logical.Storage, name string) (*oxideConfig, error) {
	raw, err := s.Get(ctx, "config/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	config := new(oxideConfig)
	if err := json.Unmarshal(raw.Value, config); err != nil {
		return nil, err
	}
	return config, nil
}

func (b *backend) pathConfigCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName := d.Get("name").(string)
	if configName == "" {
		return logical.ErrorResponse("must set config name"), nil
	}

	config, err := b.getConfig(ctx, req.Storage, configName)
	if err != nil {
		return nil, err
	}

	if config == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("config entry not found during update operation")
		}
		config = new(oxideConfig)
	}

	if platformIdentity, ok := d.GetOk("platform_identity"); ok {
		config.PlatformIdentity = platformIdentity.(string)
	}
	if host, ok := d.GetOk("host"); ok {
		config.Host = host.(string)
	}
	if token, ok := d.GetOk("token"); ok {
		config.Token = token.(string)
	}

	if _, err := parsePlatformCert([]byte(config.PlatformIdentity)); err != nil {
		return nil, fmt.Errorf("invalid platform identity cert: %w", err)
	}

	entry, err := logical.StorageEntryJSON("config/"+strings.ToLower(configName), config)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for config %s", configName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName := d.Get("name").(string)
	if configName == "" {
		return logical.ErrorResponse("must set config name"), nil
	}

	if err := req.Storage.Delete(ctx, "config/"+strings.ToLower(configName)); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName := d.Get("name").(string)
	if configName == "" {
		return logical.ErrorResponse("must set config name"), nil
	}
	config, err := b.getConfig(ctx, req.Storage, configName)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}
	data := map[string]any{
		"platform_identity": config.PlatformIdentity,
		"host":              config.Host,
	}
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.getConfig(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return config != nil, nil
}
