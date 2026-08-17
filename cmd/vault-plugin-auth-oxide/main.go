package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}

const backendHelp = "The Oxide plugin backend allows Oxide instances to authenticate to Vault using instance attestation."

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	rolePath := &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type: framework.TypeString,
			},
			"bound_silo_ids": {
				Type: framework.TypeCommaStringSlice,
			},
			"bound_project_ids": {
				Type: framework.TypeCommaStringSlice,
			},
			"bound_instance_ids": {
				Type: framework.TypeCommaStringSlice,
			},
			"bound_silo_names": {
				Type: framework.TypeCommaStringSlice,
			},
			"bound_project_names": {
				Type: framework.TypeCommaStringSlice,
			},
			"bound_instance_names": {
				Type: framework.TypeCommaStringSlice,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathRoleCreateUpdate,
			logical.UpdateOperation: b.pathRoleCreateUpdate,
			logical.DeleteOperation: b.pathRoleDelete,
			logical.ReadOperation:   b.pathRoleRead,
		},
		ExistenceCheck: b.pathRoleExistenceCheck,
	}
	tokenutil.AddTokenFields(rolePath.Fields)

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeCredential,
		Paths: []*framework.Path{
			rolePath,
			{
				Pattern: "role/?",
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ListOperation: &framework.PathOperation{
						Callback: b.pathRoleList,
					},
				},
			},
			{
				Pattern: "nonce",
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthNonce,
				},
			},
			{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"attestation": {
						Type: framework.TypeString,
					},
					"role": {
						Type: framework.TypeString,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			},
		},
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
				"nonce",
			},
		},
	}

	return &b
}

func (b *backend) role(ctx context.Context, s logical.Storage, name string) (*oxideRole, error) {
	raw, err := s.Get(ctx, "role/"+strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := new(oxideRole)
	if err := json.Unmarshal(raw.Value, role); err != nil {
		return nil, err
	}

	return role, nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("must set role name"), nil
	}

	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("role entry not found during update operation")
		}
		role = new(oxideRole)
	}

	if boundSiloIDs, ok := d.GetOk("bound_silo_ids"); ok {
		role.BoundSiloIDs = boundSiloIDs.([]string)
	}
	if boundProjectIDs, ok := d.GetOk("bound_project_ids"); ok {
		role.BoundProjectIDs = boundProjectIDs.([]string)
	}
	if boundInstanceIDs, ok := d.GetOk("bound_instance_ids"); ok {
		role.BoundInstanceIDs = boundInstanceIDs.([]string)
	}
	if boundSiloNames, ok := d.GetOk("bound_silo_names"); ok {
		role.BoundSiloNames = boundSiloNames.([]string)
	}
	if boundProjectNames, ok := d.GetOk("bound_project_names"); ok {
		role.BoundProjectNames = boundProjectNames.([]string)
	}
	if boundInstanceNames, ok := d.GetOk("bound_instance_names"); ok {
		role.BoundInstanceNames = boundInstanceNames.([]string)
	}

	if err := role.ParseTokenFields(req, d); err != nil {
		return nil, err
	}

	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(roleName), role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("failed to create storage entry for role %s", roleName)
	}
	if err = req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("must set role name"), nil
	}

	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("must set role name"), nil
	}
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	data := map[string]any{
		"bound_silo_ids":       role.BoundSiloIDs,
		"bound_project_ids":    role.BoundProjectIDs,
		"bound_instance_ids":   role.BoundInstanceIDs,
		"bound_silo_names":     role.BoundSiloNames,
		"bound_project_names":  role.BoundProjectNames,
		"bound_instance_names": role.BoundInstanceNames,
	}
	role.PopulateTokenData(data)
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.role(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathAuthNonce(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{}, nil
}

func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	attestation := d.Get("attestation").(string)

	instanceDetails, err := b.verifyAttestation(ctx, attestation)
	if err != nil {
		return nil, logical.ErrInvalidCredentials
	}

	roleName := d.Get("role").(string)
	role, err := b.role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, logical.ErrInvalidCredentials
	}
	if err := b.verifyAuthRole(role, instanceDetails); err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"instanceID":   instanceDetails.InstanceID,
		"projectID":    instanceDetails.ProjectID,
		"siloID":       instanceDetails.SiloID,
		"instanceName": instanceDetails.InstanceName,
		"projectName":  instanceDetails.ProjectName,
		"siloName":     instanceDetails.SiloName,
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

func (b *backend) verifyAuthRole(role *oxideRole, details instanceDetails) error {
	if role.BoundSiloIDs != nil && !slices.Contains(role.BoundSiloIDs, details.SiloID) {
		return logical.CodedError(http.StatusForbidden, "silo id not authorized")
	}
	if role.BoundProjectIDs != nil && !slices.Contains(role.BoundProjectIDs, details.ProjectID) {
		return logical.CodedError(http.StatusForbidden, "project id not authorized")
	}
	if role.BoundInstanceIDs != nil && !slices.Contains(role.BoundInstanceIDs, details.InstanceID) {
		return logical.CodedError(http.StatusForbidden, "instance id not authorized")
	}
	if role.BoundSiloNames != nil && !slices.Contains(role.BoundSiloIDs, details.SiloName) {
		return logical.CodedError(http.StatusForbidden, "silo name not authorized")
	}
	if role.BoundProjectNames != nil && !slices.Contains(role.BoundProjectNames, details.ProjectName) {
		return logical.CodedError(http.StatusForbidden, "project name not authorized")
	}
	if role.BoundInstanceNames != nil && !slices.Contains(role.BoundInstanceNames, details.InstanceName) {
		return logical.CodedError(http.StatusForbidden, "instance name not authorized")
	}
	return nil
}

func (b *backend) verifyAttestation(ctx context.Context, _ string) (instanceDetails, error) {
	return instanceDetails{
		SiloID:       "0001",
		ProjectID:    "0002",
		InstanceID:   "0003",
		SiloName:     "my-silo",
		ProjectName:  "my-project",
		InstanceName: "my-instance",
	}, nil
}

type instanceDetails struct {
	InstanceID string
	ProjectID  string
	SiloID     string

	InstanceName string
	ProjectName  string
	SiloName     string
}

type oxideRole struct {
	tokenutil.TokenParams

	BoundSiloIDs       []string `json:"bound_silo_ids"`
	BoundProjectIDs    []string `json:"bound_project_ids"`
	BoundInstanceIDs   []string `json:"bound_instance_ids"`
	BoundSiloNames     []string `json:"bound_silo_names"`
	BoundProjectNames  []string `json:"bound_project_names"`
	BoundInstanceNames []string `json:"bound_instance_names"`
}
