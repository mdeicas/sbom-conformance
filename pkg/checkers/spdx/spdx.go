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

package spdx

import (
	"github.com/google/sbom-conformance/pkg/checkers/common"
	types "github.com/google/sbom-conformance/pkg/checkers/types"
	"github.com/google/sbom-conformance/pkg/util"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type SPDXChecker struct {
	Name           string                     `json:"name"`
	TopLevelChecks []*types.TopLevelCheck     `json:"topLevelChecks"`
	PkgLevelChecks []*types.PackageLevelCheck `json:"pkgLevelChecks"`

	// Contains all issues
	Issues []*types.NonConformantField `json:"issues"`

	// Contains results of the packages in the SBOM.
	PkgResults []*types.PkgResult `json:"pkgResults"`
}

func (spdxChecker *SPDXChecker) InitChecks() {
	topLevelChecks := []*types.TopLevelCheck{
		{
			Name: "Check that the SBOM has an SPDX version",
			Impl: common.SBOMHasSPDXVersion,
		},
		{
			Name: "Check that the SBOM has a data license",
			Impl: common.SBOMHasDataLicense,
		},
		{
			Name: "Check that the SBOM has an SPDXIdentifier",
			Impl: common.SBOMHasSPDXIdentifier,
		},
		{
			Name: "Check that the SBOM has a Document Name",
			Impl: common.SBOMHasDocumentName,
		},
		{
			Name: "Check that the SBOM has a Document Namespace",
			Impl: common.SBOMHasDocumentNamespace,
		},
		{
			Name: "Check that the SBOM has at least one creator",
			Impl: common.SBOMHasAtLeastOneCreator,
		},
		{
			Name: "Check that the SBOMs creator is formatted correctly",
			Impl: common.SBOMHasCorrectCreationInfo,
		},
	}
	spdxChecker.TopLevelChecks = topLevelChecks

	packageLevelChecks := []*types.PackageLevelCheck{
		{
			Name: "Check that SBOM packages have a name",
			Impl: common.MustHaveName,
		},
		{
			Name: "Check that SBOM packages' ID is correctly formatted",
			Impl: common.CheckSPDXID,
		},
		{
			Name: "Check that SBOM packages' verification code is correctly formatted",
			Impl: CheckVerificationCode,
		},
		{
			Name: "Check that SBOM packages' download location is correctly formatted",
			Impl: CheckDownloadLocation,
		},
	}

	spdxChecker.PkgLevelChecks = packageLevelChecks
}

func (spdxChecker *SPDXChecker) RunTopLevelChecks(doc *v23.Document) {
	for _, check := range spdxChecker.TopLevelChecks {
		issues := check.Impl(doc, types.SPDX)
		for _, issue := range issues {
			issue.CheckName = check.Name
		}
		spdxChecker.Issues = append(spdxChecker.Issues, issues...)
	}
}

func (spdxChecker *SPDXChecker) GetIssues() []*types.NonConformantField {
	return spdxChecker.Issues
}

// Returns the spdxCheckers checks as strings.
func (spdxChecker *SPDXChecker) GetChecks() []string {
	allChecks := make([]string, 0)
	for _, topLevelCheck := range spdxChecker.TopLevelChecks {
		allChecks = append(allChecks, topLevelCheck.Name)
	}
	for _, pkgLevelCheck := range spdxChecker.PkgLevelChecks {
		allChecks = append(allChecks, pkgLevelCheck.Name)
	}
	return allChecks
}

func (spdxChecker *SPDXChecker) GetTopLevelChecks() []string {
	checks := make([]string, 0)
	for _, topLevelCheck := range spdxChecker.TopLevelChecks {
		checks = append(checks, topLevelCheck.Name)
	}
	return checks
}

func (spdxChecker *SPDXChecker) GetPackageLevelChecks() []string {
	checks := make([]string, 0)
	for _, topLevelCheck := range spdxChecker.PkgLevelChecks {
		checks = append(checks, topLevelCheck.Name)
	}
	return checks
}

func (spdxChecker *SPDXChecker) SpecName() string {
	return spdxChecker.Name
}

func (spdxChecker *SPDXChecker) GetPackages() []*types.PkgResult {
	return spdxChecker.PkgResults
}

func (spdxChecker *SPDXChecker) CheckPackages(doc *v23.Document) {
	spdxChecker.PkgResults = util.RunPkgLevelChecks(
		doc,
		spdxChecker.PkgLevelChecks,
		spdxChecker.Name,
	)
}
