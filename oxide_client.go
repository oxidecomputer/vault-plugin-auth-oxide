package oxideauth

import (
	"context"

	"github.com/oxidecomputer/oxide.go/oxide"
)

//go:generate go tool -modfile=tools/go.mod mockgen -source=oxide_client.go -destination=oxide_client_mock_test.go -package=oxideauth -mock_names=oxideClient=MockOxideClient
type oxideClient interface {
	InstanceView(context.Context, oxide.InstanceViewParams) (*oxide.Instance, error)
	ProjectView(context.Context, oxide.ProjectViewParams) (*oxide.Project, error)
}
