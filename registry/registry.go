package registry

import (
	"github.com/google/sbom-conformance/pkg/checkers/base"
)

var registry map[string]base.SpecChecker

// GetRegistry returns the registered spec checkers
func GetRegistry() map[string]base.SpecChecker {
  return registry
}

// AddToRegistry registers a SpecChecker. The name sould be lower case and not contain spaces.
func AddToRegistry(name string, checker base.SpecChecker) {
  registry[name] = checker
}
