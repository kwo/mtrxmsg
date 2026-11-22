// Package version reports build and runtime version information.
package version

import (
	"runtime"
	"strings"
)

var (
	buildVersion    = "devel"
	buildCommitHash = "unknown"
	buildCommitDate = "unknown"
)

// Line returns the version, with build and runtime details if requested.
func Line(details bool) string {
	if !details {
		return buildVersion
	}
	return strings.Join([]string{
		buildVersion,
		buildCommitHash[:min(8, len(buildCommitHash))],
		buildCommitDate,
		runtime.Version(),
	}, " ")
}
