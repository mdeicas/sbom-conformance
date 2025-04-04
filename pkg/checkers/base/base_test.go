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

package base

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	types "github.com/google/sbom-conformance/pkg/checkers/types"
)

func TestDeduplicatePackageResults(t *testing.T) {
	t.Parallel()
	licenseName := "Other License"
	spec := "Google"
	packageResults := []*types.PkgResult{
		{
			Package: &types.Package{
				Name: "pkg1",
			},
			Errors: []*types.NonConformantField{
				types.OtherLicenseError(
					licenseName,
					spec,
					"License Cross Reference is required.",
				),
				types.OtherLicenseError(
					licenseName,
					spec,
					"License Cross Reference is required.",
				),
			},
		},
	}
	deduplicated := deduplicatePackageResults(packageResults)
	if len(deduplicated) != 1 {
		t.Fatalf("There should only be 1 deduplicated pkgResult. Found %d", len(deduplicated))
	}
	if len(deduplicated[0].Errors) != 1 {
		t.Fatalf("There should only be 1 error. Found %d", len(deduplicated[0].Errors))
	}
	if len(deduplicated[0].Errors[0].ReportedBySpec) != 1 {
		t.Fatalf(
			"There should only be 1 spec. Found %d",
			len(deduplicated[0].Errors[0].ReportedBySpec),
		)
	}
	if deduplicated[0].Errors[0].ReportedBySpec[0] != "Google" {
		t.Errorf(
			"The spec should be 'Google' but is '%s'",
			deduplicated[0].Errors[0].ReportedBySpec[0],
		)
	}
}

func simpleError(
	reportedBySpec []string,
	errorType, errorMsg, checkName string,
) *types.NonConformantField {
	return &types.NonConformantField{
		ReportedBySpec: reportedBySpec,
		Error: &types.FieldError{
			ErrorType: errorType,
			ErrorMsg:  errorMsg,
		},
		CheckName: checkName,
	}
}

func TestMergePkgResults(t *testing.T) {
	t.Parallel()
	type input struct {
		pkgs     []*types.PkgResult
		expected []*types.PkgResult
	}

	inputs := []input{
		{
			pkgs: []*types.PkgResult{
				{
					Package: &types.Package{
						Name: "packagename1",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec1"}, "type1", "msg1", "checkName1"),
						simpleError([]string{"spec1"}, "type2", "msg2", "checkName2"),
						simpleError([]string{"spec1"}, "type3", "msg3", "checkName3"),
					},
				},
				{
					Package: &types.Package{
						Name: "packagename1",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec2"}, "type11", "msg11", "checkName111"),
						simpleError([]string{"spec2"}, "type22", "msg22", "checkName222"),
						simpleError([]string{"spec2"}, "type33", "msg33", "checkName333"),
						simpleError([]string{"spec2"}, "type44", "msg44", "checkName444"),
					},
				},
				{
					Package: &types.Package{
						Name: "packagename2",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec20"}, "type10", "msg10", "checkName1110"),
						simpleError([]string{"spec20"}, "type20", "msg20", "checkName2220"),
						simpleError([]string{"spec20"}, "type30", "msg30", "checkName3330"),
						simpleError([]string{"spec20"}, "type40", "msg40", "checkName4440"),
					},
				},
			},
			expected: []*types.PkgResult{
				{
					Package: &types.Package{
						Name: "packagename1",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec1"}, "type1", "msg1", "checkName1"),
						simpleError([]string{"spec1"}, "type2", "msg2", "checkName2"),
						simpleError([]string{"spec1"}, "type3", "msg3", "checkName3"),
						simpleError([]string{"spec2"}, "type11", "msg11", "checkName111"),
						simpleError([]string{"spec2"}, "type22", "msg22", "checkName222"),
						simpleError([]string{"spec2"}, "type33", "msg33", "checkName333"),
						simpleError([]string{"spec2"}, "type44", "msg44", "checkName444"),
					},
				},
				{
					Package: &types.Package{
						Name: "packagename2",
					},
					Errors: []*types.NonConformantField{
						simpleError([]string{"spec20"}, "type10", "msg10", "checkName1110"),
						simpleError([]string{"spec20"}, "type20", "msg20", "checkName2220"),
						simpleError([]string{"spec20"}, "type30", "msg30", "checkName3330"),
						simpleError([]string{"spec20"}, "type40", "msg40", "checkName4440"),
					},
				},
			},
		},
	}
	for _, inp := range inputs {
		got := mergePkgResults(inp.pkgs)
		if len(got) != 2 {
			t.Errorf("We expected 2 PkgResults, but we got %d", len(got))
		}
		for i := range got {
			if !CompareTwoPkgResults(t, got[i], inp.expected[i]) {
				t.Errorf("got pkg %d is wrong", i)
			}
		}
	}
}

// This is a primitive utility to compare two pkgResults.
// Returns "false" if the two pkgResults are not identical.
// Only used for testing.
func CompareTwoPkgResults(t *testing.T, got, expected *types.PkgResult) bool {
	t.Helper()
	if got.Package.Name != expected.Package.Name && got.Package.SpdxID != expected.Package.SpdxID {
		t.Log("The two packages have different names")
		return false
	}
	for i := range got.Errors {
		pkg1ErrorNil := got.Errors[i].Error == nil
		pkg2ErrorNil := expected.Errors[i].Error == nil
		bothErrorAreNilOrNot := pkg1ErrorNil == pkg2ErrorNil
		if !bothErrorAreNilOrNot {
			t.Logf("error %d bothErrorAreNilOrNot: %t\n", i, bothErrorAreNilOrNot)
			return false
		}
		if got.Errors[i].Error.ErrorType != expected.Errors[i].Error.ErrorType {
			t.Logf("error %d Error.ErrorType is not identical\n", i)
			return false
		}
		if got.Errors[i].Error.ErrorMsg != expected.Errors[i].Error.ErrorMsg {
			t.Logf("error %d Error.ErrorMsg is not identical\n", i)
			return false
		}
		for j := range got.Errors[i].ReportedBySpec {
			if !strings.EqualFold(
				got.Errors[i].ReportedBySpec[j],
				expected.Errors[i].ReportedBySpec[j],
			) {
				t.Logf("error %d spec %d is not correct. got=%s and expected=%s\n",
					i, j, got.Errors[i].ReportedBySpec[j], expected.Errors[j].ReportedBySpec[j])
				return false
			}
		}
		if got.Errors[i].CheckName != expected.Errors[i].CheckName {
			t.Logf("error %d CheckName is not correct \n", i)
		}
	}
	return true
}

// e2e test for the EO checker.
//
//nolint:all
func TestEOChecker(t *testing.T) {
	sbom := "simple.json"
	checker, err := NewChecker(WithEOChecker())
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sboms", sbom))
	if err != nil {
		panic(fmt.Errorf("error opening File: %w", err))
	}
	defer file.Close()
	checker, err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()

	expectedCheckNames := []string{
		"Check that the SBOM has a version",
		"Check that the SBOM has an SPDX version",
		"Check that the SBOM has at least one creator",
		"Check that the SBOMs creator is formatted correctly",
		"Check that the SBOMs packages are correctly formatted",
		"Check that SBOM packages have a name",
		"Check that SBOM packages have a valid version",
		"Check that 'Google' is spelled correctly if it is the supplier of packages",
		"Check that SBOM packages have external references",
	}

	checksInRun := checker.GetAllChecks()
	if len(checksInRun) != len(expectedCheckNames) {
		t.Fatalf(
			"This spec should have %d checks but had %d",
			len(expectedCheckNames),
			len(checksInRun),
		)
	}

	for _, checkInRun := range checksInRun {
		if !slices.Contains(expectedCheckNames, checkInRun.Name) {
			t.Errorf("The EO checks should include %s but do not", checkInRun.Name)
		}
	}

	expectedTextSummary := `Analyzed SBOM package with 4 packages. 4 of these packages failed the conformance checks.

Top-level conformance issues:
Creator organization is Some Other Company, but should always be 'Google LLC'.. [EO]

Conformance issues in packages:
1/4 package failed: has no PackageName field
4/4 packages failed: has no PackageExternalReferences field
`

	results := checker.Results()
	if !strings.EqualFold(expectedTextSummary, results.TextSummary) {
		t.Errorf(
			"The text summary was not as expected. \nWas:\n'%s'\nExpected:\n'%s'\n",
			results.TextSummary,
			expectedTextSummary,
		)
	}

	if results.Summary.TotalSBOMPackages != 4 {
		t.Errorf("There should be 4 TotalSBOMPackages but the results only had %d\n",
			results.Summary.TotalSBOMPackages)
	}
	if results.Summary.FailedSBOMPackages != 4 {
		t.Errorf("There should be 4 FailedSBOMPackages but the results only had %d\n",
			results.Summary.FailedSBOMPackages)
	}
	if len(results.Summary.SpecSummaries) != 1 {
		t.Errorf("There should be a single specsummary for 'EO' but there were %d\n",
			len(results.Summary.SpecSummaries))
	}
	if results.Summary.SpecSummaries["EO"].Conformant != false {
		t.Errorf("The 'EO' spec summary should be Conformant=true but was Conformant=%t\n",
			results.Summary.SpecSummaries["EO"].Conformant)
	}
	if results.Summary.SpecSummaries["EO"].PassedChecks != 7 {
		t.Errorf("The 'EO' spec summary should be PassedChecks=7 but was PassedChecks=%d\n",
			results.Summary.SpecSummaries["EO"].PassedChecks)
	}
	if results.Summary.SpecSummaries["EO"].TotalChecks != len(expectedCheckNames) {
		t.Errorf("The 'EO' spec summary should be TotalChecks=%d but was TotalChecks=%d\n",
			len(expectedCheckNames),
			results.Summary.SpecSummaries["EO"].TotalChecks)
	}
	if len(results.PkgResults) != results.Summary.FailedSBOMPackages {
		t.Errorf(
			"len(results.PkgResults) should be the same as results.Summary.FailedSBOMPackages but was %d\n",
			len(results.PkgResults),
		)
	}

	// First package findings
	packageName := results.PkgResults[0].Package.Name
	if packageName != "Some Package" {
		t.Errorf("The first package should be named 'Some Package' but was named '%s'", packageName)
	}
	if len(results.PkgResults[0].Errors) != 1 {
		t.Error("There should only be one error")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorMsg != "has no PackageExternalReferences field" {
		t.Errorf("Should be 'has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[0].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Second package findings
	packageName = results.PkgResults[1].Package.Name
	if results.PkgResults[1].Package.Name != "" {
		t.Errorf("The second package should be named '' but was named %s", packageName)
	}
	if len(results.PkgResults[1].Errors) != 2 {
		t.Error("There should be two errors")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorMsg != "has no PackageName field" {
		t.Errorf("Should be 'has no PackageName field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[1].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorMsg != "has no PackageExternalReferences field" {
		t.Errorf("Should be 'has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[1].Errors[1].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Third package findings
	packageName = results.PkgResults[2].Package.Name
	if results.PkgResults[2].Package.Name != "another package" {
		t.Errorf(
			"The third package should be named 'another package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[2].Errors) != 1 {
		t.Error("There should be two errors")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorMsg != "has no PackageExternalReferences field" {
		t.Errorf("Should be 'has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Fourth package findings
	packageName = results.PkgResults[3].Package.Name
	if results.PkgResults[3].Package.Name != "last package" {
		t.Errorf(
			"The fourth package should be named 'last package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[2].Errors) != 1 {
		t.Error("There should be two errors")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorMsg != "has no PackageExternalReferences field" {
		t.Errorf("Should be 'has no PackageExternalReferences field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"EO"}) {
		t.Errorf("The issue should be reported by EO")
	}

	// Check results.Errs.AndPacks
	if len(results.ErrsAndPacks) != 2 {
		t.Errorf(
			"The length of results.ErrsAndPacks should be 2 but is %d",
			len(results.ErrsAndPacks),
		)
	}
	expect := []string{
		"Some Package",
		"Package-1",
		"another package",
		"last package",
	}
	if !slices.Equal(results.ErrsAndPacks["has no PackageExternalReferences field"], expect) {
		t.Errorf(
			"Expected %+v but got %+v",
			expect,
			results.ErrsAndPacks["has no PackageExternalReferences field"],
		)
	}
	/*expect = []string{"Package-1"}
	if !slices.Equal(results.ErrsAndPacks["has no PackageName field"], expect) {
		t.Error("Wrong")
	}*/
}

// e2e test for the Google checker.
//
//nolint:all
func TestGoogleChecker(t *testing.T) {
	sbom := "simple.json"
	checker, err := NewChecker(WithGoogleChecker())
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sboms", sbom))
	if err != nil {
		panic(fmt.Errorf("error opening File: %w", err))
	}
	defer file.Close()
	checker, err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()

	expectedCheckNames := []string{
		"Check that the SBOM has an SPDX version",
		"Check that the SBOM has a data license",
		"Check that the SBOM has an SPDXIdentifier",
		"Check that the SBOM has a Document Name",
		"Check that the SBOM has a Document Namespace",
		"Check that the SBOM has at least one creator",
		"Check that the SBOMs creator is formatted correctly",
		"Check the SBOMs other licensing fields",
		"Check that SBOM packages have a name",
		"Check that SBOM packages' ID is correctly formatted",
		"Check that SBOM packages have specified the supplier as Google",
		"Check that SBOM packages have not left both PackageLicenseConcluded and PackageLicenseInfoFromFiles empty",
	}

	checksInRun := checker.GetAllChecks()
	if len(checksInRun) != len(expectedCheckNames) {
		t.Fatalf(
			"This spec should have %d checks but had %d",
			len(expectedCheckNames),
			len(checksInRun),
		)
	}

	for _, checkInRun := range checksInRun {
		if !slices.Contains(expectedCheckNames, checkInRun.Name) {
			t.Errorf("The Google checks should include %s but do not", checkInRun.Name)
		}
	}

	expectedTextSummary := `Analyzed SBOM package with 4 packages. 4 of these packages failed the conformance checks.

Top-level conformance issues:
Creator organization is Some Other Company, but should always be 'Google LLC'.. [Google]
SBOM has no License Identifier field. [Google]

Conformance issues in packages:
1/4 package failed: has neither Concluded License nor License From Files. Both of these cannot be absent from a package.
1/4 package failed: has no PackageName field
4/4 packages failed: has no PackageSupplier field
`

	results := checker.Results()
	if !strings.EqualFold(expectedTextSummary, results.TextSummary) {
		t.Errorf(
			"The text summary was not as expected. \nWas:\n'%s'\nExpected:\n'%s'\n",
			results.TextSummary,
			expectedTextSummary,
		)
	}

	if results.Summary.TotalSBOMPackages != 4 {
		t.Errorf("There should be 4 TotalSBOMPackages but the results only had %d\n",
			results.Summary.TotalSBOMPackages)
	}
	if results.Summary.FailedSBOMPackages != 4 {
		t.Errorf("There should be 4 FailedSBOMPackages but the results only had %d\n",
			results.Summary.FailedSBOMPackages)
	}
	if len(results.Summary.SpecSummaries) != 1 {
		t.Errorf("There should be a single specsummary for 'Google' but there were %d\n",
			len(results.Summary.SpecSummaries))
	}
	if results.Summary.SpecSummaries["Google"].Conformant != false {
		t.Errorf("The 'Google' spec summary should be Conformant=true but was Conformant=%t\n",
			results.Summary.SpecSummaries["Google"].Conformant)
	}
	if results.Summary.SpecSummaries["Google"].PassedChecks != 7 {
		t.Errorf("The 'Google' spec summary should be PassedChecks=7 but was PassedChecks=%d\n",
			results.Summary.SpecSummaries["Google"].PassedChecks)
	}
	if results.Summary.SpecSummaries["Google"].TotalChecks != len(expectedCheckNames) {
		t.Errorf("The 'Google' spec summary should be TotalChecks=%d but was TotalChecks=%d\n",
			len(expectedCheckNames),
			results.Summary.SpecSummaries["Google"].TotalChecks)
	}
	if len(results.PkgResults) != results.Summary.FailedSBOMPackages {
		t.Errorf(
			"len(results.PkgResults) should be the same as results.Summary.FailedSBOMPackages but was %d\n",
			len(results.PkgResults),
		)
	}

	// First package findings
	packageName := results.PkgResults[0].Package.Name
	if results.PkgResults[0].Package.Name != "Some Package" {
		t.Errorf("The first package should be named 'Some Package' but was named '%s'", packageName)
	}
	if len(results.PkgResults[0].Errors) != 2 {
		t.Error("There should be two SBOM issues")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[0].Errors[0].Error.ErrorMsg != "has no PackageSupplier field" {
		t.Errorf("Should be 'has no PackageSupplier field' ErrorMsg")
	}
	if results.PkgResults[0].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[0].Errors[1].Error.ErrorMsg != "has neither Concluded License nor License From Files. Both of these cannot be absent from a package." {
		t.Errorf(
			"Should be 'has neither Concluded License nor License From Files. Both of these cannot be absent from a package.' ErrorMsg",
		)
	}
	if !slices.Equal(results.PkgResults[0].Errors[0].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}
	if !slices.Equal(results.PkgResults[0].Errors[1].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}

	// Second package findings
	packageName = results.PkgResults[1].Package.Name
	if results.PkgResults[1].Package.Name != "" {
		t.Errorf("The first package should be named '' but was named '%s'", packageName)
	}
	if len(results.PkgResults[1].Errors) != 2 {
		t.Error("There should only be two SBOM issues")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorMsg != "has no PackageName field" {
		t.Errorf("Should be 'has no PackageName field' ErrorMsg")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorMsg != "has no PackageSupplier field" {
		t.Errorf("Should be 'has no PackageSupplier field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[1].Errors[0].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}
	if !slices.Equal(results.PkgResults[1].Errors[1].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}

	// Third package findings
	packageName = results.PkgResults[2].Package.Name
	if results.PkgResults[2].Package.Name != "another package" {
		t.Errorf(
			"The second package should be named 'another package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[2].Errors) != 1 {
		t.Error("There should only be one error")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorMsg != "has no PackageSupplier field" {
		t.Errorf("Should be 'has no PackageSupplier field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}

	// Fourth package findings
	packageName = results.PkgResults[3].Package.Name
	if results.PkgResults[3].Package.Name != "last package" {
		t.Errorf(
			"The fourth package should be named 'last package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[3].Errors) != 1 {
		t.Error("There should only be one error")
	}
	if results.PkgResults[3].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[3].Errors[0].Error.ErrorMsg != "has no PackageSupplier field" {
		t.Errorf("Should be 'has no PackageSupplier field' ErrorMsg")
	}
	if !slices.Equal(results.PkgResults[3].Errors[0].ReportedBySpec, []string{"Google"}) {
		t.Errorf("The issue should be reported by Google")
	}

	// Check results.Errs.AndPacks
	if len(results.ErrsAndPacks) != 3 {
		t.Errorf(
			"The length of results.ErrsAndPacks should be 3 but is %d",
			len(results.ErrsAndPacks),
		)
	}
	expect := []string{
		"Some Package",
		"Package-1",
		"another package",
		"last package",
	}
	if !slices.Equal(results.ErrsAndPacks["has no PackageSupplier field"], expect) {
		t.Error("Wrong")
	}
	/*expect = []string{"Package"}
	if !slices.Equal(results.ErrsAndPacks["has neither Concluded License nor License From Files. Both of these cannot be absent from a package."], expect) {
		t.Error("Wrong")
	}
	expect = []string{"Package-1"}
	if !slices.Equal(results.ErrsAndPacks["has no PackageName field"], expect) {
		t.Error("Wrong")
	}*/
}

// e2e test for the SPDX checker.
//
//nolint:all
func TestSPDXChecker(t *testing.T) {
	sbom := "simple.json"
	checker, err := NewChecker(WithSPDXChecker())
	if err != nil {
		panic(err)
	}

	file, err := os.Open(filepath.Join("..", "..", "..", "testdata", "sboms", sbom))
	if err != nil {
		panic(fmt.Errorf("error opening File: %w", err))
	}
	defer file.Close()
	checker, err = checker.SetSBOM(file)
	if err != nil {
		panic(err)
	}

	// Run checks
	checker.RunChecks()

	expectedCheckNames := []string{
		"Check that the SBOM has an SPDX version",
		"Check that the SBOM has a data license",
		"Check that the SBOM has an SPDXIdentifier",
		"Check that the SBOM has a Document Name",
		"Check that the SBOM has a Document Namespace",
		"Check that the SBOM has at least one creator",
		"Check that the SBOMs creator is formatted correctly",
		"Check that SBOM packages have a name",
		"Check that SBOM packages' ID is correctly formatted",
		"Check that SBOM packages' verification code is correctly formatted",
		"Check that SBOM packages' download location is correctly formatted",
	}

	checksInRun := checker.GetAllChecks()
	if len(checksInRun) != len(expectedCheckNames) {
		t.Fatalf(
			"This spec should have %d checks but had %d",
			len(expectedCheckNames),
			len(checksInRun),
		)
	}

	for _, checkInRun := range checksInRun {
		if !slices.Contains(expectedCheckNames, checkInRun.Name) {
			t.Errorf("The SPDX checks should include %s but do not", checkInRun.Name)
		}
	}

	expectedTextSummary := `Analyzed SBOM package with 4 packages. 3 of these packages failed the conformance checks.

Top-level conformance issues:
Creator organization is Some Other Company, but should always be 'Google LLC'.. [SPDX]

Conformance issues in packages:
1/4 package failed: has no PackageName field
3/4 packages failed: has no PackageDownloadLocation field
`

	results := checker.Results()
	if !strings.EqualFold(expectedTextSummary, results.TextSummary) {
		t.Errorf(
			"The text summary was not as expected. \nWas:\n'%s'\nExpected:\n'%s'\n",
			results.TextSummary,
			expectedTextSummary,
		)
	}

	if results.Summary.TotalSBOMPackages != 4 {
		t.Errorf("There should be 4 TotalSBOMPackages but the results only had %d\n",
			results.Summary.TotalSBOMPackages)
	}
	if results.Summary.FailedSBOMPackages != 3 {
		t.Errorf("There should be 3 FailedSBOMPackages but the results only had %d\n",
			results.Summary.FailedSBOMPackages)
	}
	if len(results.Summary.SpecSummaries) != 1 {
		t.Errorf("There should be a single specsummary for 'SPDX' but there were %d\n",
			len(results.Summary.SpecSummaries))
	}
	if results.Summary.SpecSummaries["SPDX"].Conformant != false {
		t.Errorf("The 'SPDX' spec summary should be Conformant=true but was Conformant=%t\n",
			results.Summary.SpecSummaries["SPDX"].Conformant)
	}
	if results.Summary.SpecSummaries["SPDX"].PassedChecks != 8 {
		t.Errorf("The 'SPDX' spec summary should be PassedChecks=8 but was PassedChecks=%d\n",
			results.Summary.SpecSummaries["SPDX"].PassedChecks)
	}
	if results.Summary.SpecSummaries["SPDX"].TotalChecks != len(expectedCheckNames) {
		t.Errorf("The 'SPDX' spec summary should be TotalChecks=%d but was TotalChecks=%d\n",
			len(expectedCheckNames),
			results.Summary.SpecSummaries["SPDX"].TotalChecks)
	}
	if len(results.PkgResults) != 4 {
		t.Errorf("len(results.PkgResults) should be 4 but was %d\n",
			len(results.PkgResults))
	}

	// First package findings
	packageName := results.PkgResults[0].Package.Name
	if results.PkgResults[0].Package.Name != "Some Package" {
		t.Errorf("The first package should be named 'Some Package' but was named '%s'", packageName)
	}
	if len(results.PkgResults[0].Errors) != 0 {
		t.Errorf(
			"There should be no SBOM issues but there are %d\n",
			len(results.PkgResults[0].Errors),
		)
	}

	// Second package findings
	packageName = results.PkgResults[1].Package.Name
	if results.PkgResults[1].Package.Name != "" {
		t.Errorf("The first package should be named '' but was named '%s'", packageName)
	}
	if len(results.PkgResults[1].Errors) != 2 {
		t.Errorf(
			"There should be two SBOM issues but there are %d\n",
			len(results.PkgResults[1].Errors),
		)
	}
	if results.PkgResults[1].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[0].Error.ErrorMsg != "has no PackageName field" {
		t.Errorf(
			"Should be 'has no PackageName field' ErrorMsg but was %s\n",
			results.PkgResults[1].Errors[0].Error.ErrorMsg,
		)
	}
	if results.PkgResults[1].Errors[1].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[1].Errors[1].Error.ErrorMsg != "has no PackageDownloadLocation field" {
		t.Errorf(
			"Should be 'has no PackageDownloadLocation field' ErrorMsg but was %s\n",
			results.PkgResults[1].Errors[1].Error.ErrorMsg,
		)
	}
	if !slices.Equal(results.PkgResults[1].Errors[0].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}
	if !slices.Equal(results.PkgResults[1].Errors[1].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}

	// Third package findings
	packageName = results.PkgResults[2].Package.Name
	if results.PkgResults[2].Package.Name != "another package" {
		t.Errorf(
			"The second package should be named 'another package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[2].Errors) != 1 {
		t.Errorf(
			"There should be one SBOM issues but there are %d\n",
			len(results.PkgResults[2].Errors),
		)
	}
	if results.PkgResults[2].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[2].Errors[0].Error.ErrorMsg != "has no PackageDownloadLocation field" {
		t.Errorf(
			"Should be 'has no PackageDownloadLocation field' ErrorMsg but was %s\n",
			results.PkgResults[2].Errors[0].Error.ErrorMsg,
		)
	}
	if !slices.Equal(results.PkgResults[2].Errors[0].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}

	// Fourth package findings
	packageName = results.PkgResults[3].Package.Name
	if results.PkgResults[3].Package.Name != "last package" {
		t.Errorf(
			"The fourth package should be named 'last package' but was named '%s'",
			packageName,
		)
	}
	if len(results.PkgResults[3].Errors) != 1 {
		t.Errorf(
			"There should be one SBOM issues but there are %d\n",
			len(results.PkgResults[3].Errors),
		)
	}
	if results.PkgResults[3].Errors[0].Error.ErrorType != "missingField" {
		t.Errorf("Should be missingField ErrorType")
	}
	if results.PkgResults[3].Errors[0].Error.ErrorMsg != "has no PackageDownloadLocation field" {
		t.Errorf(
			"Should be 'has no PackageDownloadLocation field' ErrorMsg but was %s\n",
			results.PkgResults[3].Errors[0].Error.ErrorMsg,
		)
	}
	if !slices.Equal(results.PkgResults[3].Errors[0].ReportedBySpec, []string{"SPDX"}) {
		t.Errorf("The issue should be reported by SPDX")
	}
}
