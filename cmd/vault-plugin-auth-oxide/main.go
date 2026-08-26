package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.com/oxidecomputer/oxide.go/oxide"
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
	b.locks = locksutil.CreateLocks()
	return b, nil
}

type backend struct {
	*framework.Backend

	locks []*locksutil.LockEntry
}

const backendHelp = "The Oxide plugin backend allows Oxide instances to authenticate to Vault using instance attestation."

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	configPath := &framework.Path{
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
	rolePath := &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type: framework.TypeString,
			},
			"config": {
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
			configPath,
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
					"nonce": {
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

func (b *backend) verifyAuthRole(role *oxideRole, details *instanceDetails) error {
	if role.BoundProjectIDs != nil && !slices.Contains(role.BoundProjectIDs, details.ProjectID) {
		return logical.CodedError(http.StatusForbidden, "project id not authorized")
	}
	if role.BoundInstanceIDs != nil && !slices.Contains(role.BoundInstanceIDs, details.InstanceID) {
		return logical.CodedError(http.StatusForbidden, "instance id not authorized")
	}
	if role.BoundProjectNames != nil && !slices.Contains(role.BoundProjectNames, details.ProjectName) {
		return logical.CodedError(http.StatusForbidden, "project name not authorized")
	}
	if role.BoundInstanceNames != nil && !slices.Contains(role.BoundInstanceNames, details.InstanceName) {
		return logical.CodedError(http.StatusForbidden, "instance name not authorized")
	}
	return nil
}

type rawAttestation struct {
	Attest attestation `json:"Attest"`
}

func (a *rawAttestation) parse() (*parsedAttestation, error) {
	certs := make([]*x509.Certificate, len(a.Attest.CertChain))
	for idx, certBytes := range a.Attest.CertChain {
		cert, err := x509.ParseCertificate(intSliceToBytes(certBytes))
		if err != nil {
			return nil, err
		}
		certs[idx] = cert
	}

	var platformLog []byte
	var instanceLog []byte
	var conf vmInstanceConf

	for _, log := range a.Attest.MeasurementLogs {
		switch log.Rot {
		case "OxidePlatform":
			platformLog = intSliceToBytes(log.Data)
		case "OxideInstance":
			instanceLog = intSliceToBytes(log.Data)
			if err := json.Unmarshal(instanceLog, &conf); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("got unexpected rot type %q", log.Rot)
		}
	}

	return &parsedAttestation{
		signature:      intSliceToBytes(a.Attest.Attestation),
		certChain:      certs,
		platformLog:    platformLog,
		instanceLog:    instanceLog,
		vmInstanceConf: conf,
	}, nil
}

func intSliceToBytes(in []int) []byte {
	b := make([]byte, len(in))
	for idx, i := range in {
		b[idx] = byte(i)
	}
	return b
}

type attestation struct {
	Attestation     []int            `json:"attestation"`
	CertChain       [][]int          `json:"cert_chain"`
	MeasurementLogs []measurementLog `json:"measurement_logs"`
}

type measurementLog struct {
	Rot  string `json:"rot"`
	Data []int  `json:"data"`
}

type parsedAttestation struct {
	signature      []byte
	certChain      []*x509.Certificate
	platformLog    []byte
	instanceLog    []byte
	vmInstanceConf vmInstanceConf
}

type vmInstanceConf struct {
	Uuid    string `json:"uuid"`
	Project string `json:"project"`
	Silo    string `json:"silo"`
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

	// TODO: Verify silo

	return &instanceDetails{
		ProjectID:    instance.ProjectId,
		InstanceID:   instance.Id,
		ProjectName:  string(project.Name),
		InstanceName: string(instance.Name),
	}, nil
}

type instanceDetails struct {
	InstanceID string
	ProjectID  string

	InstanceName string
	ProjectName  string
}
