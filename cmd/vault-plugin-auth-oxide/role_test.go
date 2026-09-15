package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoleValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    oxideRole
		wantErr string
	}{
		{
			name: "valid",
			role: oxideRole{
				BoundProjectNames: []string{
					"my-project",
					"my-prefix-*",
				},
			},
		},
		{
			name:    "invalid no bound",
			role:    oxideRole{},
			wantErr: "role contains no bounds",
		},
		{
			name: "invalid bad project glob",
			role: oxideRole{
				BoundProjectNames: []string{
					"bad[glob",
				},
			},
			wantErr: "invalid project name",
		},
		{
			name: "invalid bad instance glob",
			role: oxideRole{
				BoundInstanceNames: []string{
					"bad[glob",
				},
			},
			wantErr: "invalid instance name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.role.validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

func TestRoleAuthorize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    oxideRole
		details instanceDetails
		wantErr string
	}{
		{
			name: "happy match all",
			role: oxideRole{
				BoundProjectNames:  []string{"my-project-1", "my-project-2"},
				BoundInstanceNames: []string{"my-instance-*"},
				BoundProjectIDs:    []string{"10000000-0000-0000-0000-000000000001"},
				BoundInstanceIDs:   []string{"10000000-0000-0000-0000-000000000002"},
			},
			details: instanceDetails{
				InstanceID:   "10000000-0000-0000-0000-000000000002",
				ProjectID:    "10000000-0000-0000-0000-000000000001",
				InstanceName: "my-instance-foo",
				ProjectName:  "my-project-2",
			},
			wantErr: "",
		},
		{
			name: "sad mismatch project id",
			role: oxideRole{
				BoundProjectIDs: []string{"10000000-0000-0000-0000-000000000001"},
			},
			details: instanceDetails{
				InstanceID:   "10000000-0000-0000-0000-000000000002",
				ProjectID:    "10000000-0000-0000-0000-000000000003",
				InstanceName: "my-instance-foo",
				ProjectName:  "my-project-2",
			},
			wantErr: "project id not authorized",
		},
		{
			name: "sad mismatch project name",
			role: oxideRole{
				BoundProjectNames: []string{"my-project-1"},
			},
			details: instanceDetails{
				InstanceID:   "10000000-0000-0000-0000-000000000002",
				ProjectID:    "10000000-0000-0000-0000-000000000001",
				InstanceName: "my-instance-foo",
				ProjectName:  "my-project-2",
			},
			wantErr: "project name not authorized",
		},
		{
			name: "sad mismatch instance id",
			role: oxideRole{
				BoundInstanceIDs: []string{"10000000-0000-0000-0000-000000000001"},
			},
			details: instanceDetails{
				InstanceID:   "10000000-0000-0000-0000-000000000002",
				ProjectID:    "10000000-0000-0000-0000-000000000003",
				InstanceName: "my-instance-foo",
				ProjectName:  "my-project-2",
			},
			wantErr: "instance id not authorized",
		},
		{
			name: "sad mismatch instance name",
			role: oxideRole{
				BoundInstanceNames: []string{"my-project-foo"},
			},
			details: instanceDetails{
				InstanceID:   "10000000-0000-0000-0000-000000000002",
				ProjectID:    "10000000-0000-0000-0000-000000000001",
				InstanceName: "my-instance-bar",
				ProjectName:  "my-project-2",
			},
			wantErr: "instance name not authorized",
		},
		{
			name: "sad partial match",
			role: oxideRole{
				BoundProjectNames:  []string{"my-project-1", "my-project-2"},
				BoundInstanceNames: []string{"my-instance-*"},
				BoundProjectIDs:    []string{"10000000-0000-0000-0000-000000000001"},
				BoundInstanceIDs:   []string{"10000000-0000-0000-0000-000000000002"},
			},
			details: instanceDetails{
				InstanceID:   "10000000-0000-0000-0000-000000000002",
				ProjectID:    "10000000-0000-0000-0000-000000000001",
				InstanceName: "my-instance-foo",
				ProjectName:  "my-project-3",
			},
			wantErr: "project name not authorized",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.role.authorize(&tc.details)
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}
