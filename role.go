package oxideauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/tokenutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type oxideRole struct {
	tokenutil.TokenParams

	Verifier           string   `json:"verifier"`
	BoundProjectIDs    []string `json:"bound_project_ids"`
	BoundInstanceIDs   []string `json:"bound_instance_ids"`
	BoundProjectNames  []string `json:"bound_project_names"`
	BoundInstanceNames []string `json:"bound_instance_names"`
}

func (b *backend) pathRole() *framework.Path {
	path := &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type: framework.TypeString,
			},
			"verifier": {
				Type: framework.TypeString,
			},
			"bound_project_ids": {
				Type: framework.TypeCommaStringSlice,
			},
			"bound_instance_ids": {
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
			logical.CreateOperation: b.handleRoleCreateUpdate,
			logical.UpdateOperation: b.handleRoleCreateUpdate,
			logical.DeleteOperation: b.handleRoleDelete,
			logical.ReadOperation:   b.handleRoleRead,
		},
		ExistenceCheck: b.handleRoleExistenceCheck,
	}
	tokenutil.AddTokenFields(path.Fields)

	return path
}

func (b *backend) pathListRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleRoleList,
			},
		},
	}
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*oxideRole, error) {
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

func (b *backend) handleRoleCreateUpdate(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("must set role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	if role == nil {
		if req.Operation == logical.UpdateOperation {
			return nil, errors.New("role entry not found during update operation")
		}
		role = new(oxideRole)
	}

	if verifier, ok := d.GetOk("verifier"); ok {
		role.Verifier = verifier.(string)
	}
	if role.Verifier == "" {
		return nil, fmt.Errorf("verifier field must be set")
	}

	if boundProjectIDs, ok := d.GetOk("bound_project_ids"); ok {
		role.BoundProjectIDs = boundProjectIDs.([]string)
	}
	if boundInstanceIDs, ok := d.GetOk("bound_instance_ids"); ok {
		role.BoundInstanceIDs = boundInstanceIDs.([]string)
	}
	if boundProjectNames, ok := d.GetOk("bound_project_names"); ok {
		role.BoundProjectNames = boundProjectNames.([]string)
	}
	if boundInstanceNames, ok := d.GetOk("bound_instance_names"); ok {
		role.BoundInstanceNames = boundInstanceNames.([]string)
	}

	if err := role.validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
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

func (r *oxideRole) validate() error {
	if len(r.BoundProjectIDs) == 0 && len(r.BoundInstanceIDs) == 0 &&
		len(r.BoundProjectNames) == 0 && len(r.BoundInstanceNames) == 0 {
		return errors.New("role contains no bounds")
	}
	if err := validateGlobs(r.BoundProjectNames); err != nil {
		return fmt.Errorf("invalid project name pattern(s) %q: %w", r.BoundProjectNames, err)
	}
	if err := validateGlobs(r.BoundInstanceNames); err != nil {
		return fmt.Errorf("invalid instance name pattern(s) %q: %w", r.BoundInstanceNames, err)
	}
	return nil
}

func (r *oxideRole) authorize(details *instanceDetails) error {
	if err := r.validate(); err != nil {
		return logical.CodedError(http.StatusForbidden, err.Error())
	}

	if len(r.BoundProjectIDs) > 0 && !slices.Contains(r.BoundProjectIDs, details.ProjectID) {
		return logical.CodedError(http.StatusForbidden, "project id not authorized")
	}
	if len(r.BoundInstanceIDs) > 0 && !slices.Contains(r.BoundInstanceIDs, details.InstanceID) {
		return logical.CodedError(http.StatusForbidden, "instance id not authorized")
	}
	if len(r.BoundProjectNames) > 0 && !matchGlobs(r.BoundProjectNames, details.ProjectName) {
		return logical.CodedError(http.StatusForbidden, "project name not authorized")
	}
	if len(r.BoundInstanceNames) > 0 && !matchGlobs(r.BoundInstanceNames, details.InstanceName) {
		return logical.CodedError(http.StatusForbidden, "instance name not authorized")
	}
	return nil
}

func (b *backend) handleRoleDelete(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("must set role name"), nil
	}

	if err := req.Storage.Delete(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *backend) handleRoleRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	roleName := d.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("must set role name"), nil
	}
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	data := map[string]any{
		"verifier":             role.Verifier,
		"bound_project_ids":    role.BoundProjectIDs,
		"bound_instance_ids":   role.BoundInstanceIDs,
		"bound_project_names":  role.BoundProjectNames,
		"bound_instance_names": role.BoundInstanceNames,
	}
	role.PopulateTokenData(data)
	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) handleRoleList(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) handleRoleExistenceCheck(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}
