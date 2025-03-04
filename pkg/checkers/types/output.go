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

type SpecSummary struct {
	// true if len(TotalChecks) == len(PassedChecks)
	Conformant bool `json:"conformant"`

	PassedChecks int `json:"passedChecks"`
	TotalChecks  int `json:"totalChecks"`
}

// Output is the type we convert to json when we output the results.
type Output struct {
	TextSummary        string              `json:"textSummary"`
	Summary            *Summary            `json:"summary"`
	ErrsAndPacks       map[string][]string `json:"errsAndPacks,omitempty"`
	PkgResults         []*PkgResult        `json:"pkgResults,omitempty"`
	ChecksInRun        []*CheckSummary     `json:"checksInRun"`
	TotalSBOMPackages  int                 `json:"totalSbomPackages"`
	FailedSBOMPackages int                 `json:"failedSbomPackages"`
}

type Summary struct {
	SpecSummaries      map[string]*SpecSummary `json:"specSummaries"`
	TotalSBOMPackages  int                     `json:"totalSbomPackages"`
	FailedSBOMPackages int                     `json:"failedSbomPackages"`
}

func OutputFromInput(pkgResults []*PkgResult,
	errsAndPacks map[string][]string,
	totalSBOMPkgs, failedSBOMackages int,
	checksInRun []*CheckSummary,
) *Output {
	return &Output{
		PkgResults:         pkgResults,
		ErrsAndPacks:       errsAndPacks,
		TotalSBOMPackages:  totalSBOMPkgs,
		FailedSBOMPackages: failedSBOMackages,
		ChecksInRun:        checksInRun,
	}
}
