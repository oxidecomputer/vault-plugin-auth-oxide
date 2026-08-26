package main

import (
	"context"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
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

	b.Backend = &framework.Backend{
		Help:        backendHelp,
		BackendType: logical.TypeCredential,
		Paths: []*framework.Path{
			b.pathConfig(),
			b.pathRole(),
			b.pathListRole(),
			b.pathAuthNonce(),
			b.pathAuthLogin(),
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
