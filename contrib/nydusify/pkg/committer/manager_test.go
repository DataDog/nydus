package committer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMountOptions(t *testing.T) {
	tests := []struct {
		Name         string
		Options      []string
		WantLower    string
		WantUpper    string
		WantErr      bool
		ErrSubstring string
	}{
		{
			Name: "StandardOrder",
			Options: []string{
				"workdir=/var/lib/containerd/snapshots/123/work",
				"upperdir=/var/lib/containerd/snapshots/123/fs",
				"lowerdir=/var/lib/containerd/snapshots/100/mnt",
			},
			WantLower: "/var/lib/containerd/snapshots/100/mnt",
			WantUpper: "/var/lib/containerd/snapshots/123/fs",
		},
		{
			Name: "WithVolatilePrefix",
			Options: []string{
				"volatile",
				"workdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/1443/work",
				"upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/1443/fs",
				"lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/282/mnt",
			},
			WantLower: "/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/282/mnt",
			WantUpper: "/var/lib/containerd/io.containerd.snapshotter.v1.nydus/snapshots/1443/fs",
		},
		{
			Name: "ReversedOrder",
			Options: []string{
				"lowerdir=/lower",
				"upperdir=/upper",
				"workdir=/work",
			},
			WantLower: "/lower",
			WantUpper: "/upper",
		},
		{
			Name: "MultipleLowerDirs",
			Options: []string{
				"workdir=/work",
				"upperdir=/upper",
				"lowerdir=/lower1:/lower2:/lower3",
			},
			WantLower: "/lower1:/lower2:/lower3",
			WantUpper: "/upper",
		},
		{
			Name: "WithIndexOff",
			Options: []string{
				"volatile",
				"index=off",
				"workdir=/work",
				"upperdir=/upper",
				"lowerdir=/lower",
			},
			WantLower: "/lower",
			WantUpper: "/upper",
		},
		{
			Name:         "MissingLowerDir",
			Options:      []string{"workdir=/work", "upperdir=/upper"},
			WantErr:      true,
			ErrSubstring: "missing lowerdir or upperdir",
		},
		{
			Name:         "MissingUpperDir",
			Options:      []string{"workdir=/work", "lowerdir=/lower"},
			WantErr:      true,
			ErrSubstring: "missing lowerdir or upperdir",
		},
		{
			Name:         "EmptyOptions",
			Options:      []string{},
			WantErr:      true,
			ErrSubstring: "missing lowerdir or upperdir",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			lowerDirs, upperDir, err := parseMountOptions(tt.Options)
			if tt.WantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.ErrSubstring)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.WantLower, lowerDirs)
			assert.Equal(t, tt.WantUpper, upperDir)
		})
	}
}
