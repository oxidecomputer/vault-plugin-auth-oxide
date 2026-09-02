package main

import (
	"context"
	"log"
	"os"

	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin"
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
			b.pathVerifier(),
			b.pathListVerifier(),
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
