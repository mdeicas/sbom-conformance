// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

// This is a summary of a check and the specs
// that have this check. SBOM-conformance uses
// this to display the checks a given run will
// do and the specs for each check. Some specs
// run the same checks, which is why we have
// the list of specs.
type CheckSummary struct {
	// The percentage of the packages that failed this check
	FailedPkgsPercent *float32 `json:"failedPkgsPercent,omitempty"`

	PassedHighLevel *bool `json:"passedHighLevel,omitempty"`

	Name  string   `json:"name"`
	Specs []string `json:"specs"`
}
