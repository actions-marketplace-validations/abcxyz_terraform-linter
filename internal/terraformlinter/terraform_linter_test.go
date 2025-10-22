// Copyright 2023 The Authors (see AUTHORS file)
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

package terraformlinter

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestTerraformLinter_FindViolations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		expect  string
	}{
		{
			name: "no_special_attributes",
			content: `
resource "google_project_service" "run_api" {
	service            = "run.googleapis.com"
	disable_on_destroy = true
}
				`,
		},
		{
			name: "for_each_correct",
			content: `
resource "google_project_service" "run_api" {
  for_each = toset(["name"])

  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
		},
		{
			name: "for_each_missing_newline",
			content: `
resource "google_project_service" "run_api" {
  for_each           = toset(["name"])
  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:4:3: TF051: Meta block must have an additional newline separating it from the next section.
  service            = "run.googleapis.com"
  ^
`,
		},
		{
			name: "for_each_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  for_each           = toset(["name"])
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:5:3: TF051: Meta block must have an additional newline separating it from the next section.
  disable_on_destroy = true
  ^

test.tf:4:3: TF100: Attribute must be in the meta block at the top of the definition.
  for_each           = toset(["name"])
  ^
`,
		},
		{
			name: "count_correct",
			content: `
resource "google_project_service" "run_api" {
  count = 3

  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
		},
		{
			name: "count_missing_newline",
			content: `
resource "google_project_service" "run_api" {
  count              = 3
  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:4:3: TF051: Meta block must have an additional newline separating it from the next section.
  service            = "run.googleapis.com"
  ^
`,
		},
		{
			name: "count_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  count              = 3
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:5:3: TF051: Meta block must have an additional newline separating it from the next section.
  disable_on_destroy = true
  ^

test.tf:4:3: TF100: Attribute must be in the meta block at the top of the definition.
  count              = 3
  ^
`,
		},
		{
			name: "provider_correct",
			content: `
resource "google_project_service" "run_api" {
  provider = "some_provider"

  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
		},
		{
			name: "provider_missing_newline",
			content: `
resource "google_project_service" "run_api" {
  provider           = "some_provider"
  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:4:3: TF051: Meta block must have an additional newline separating it from the next section.
  service            = "run.googleapis.com"
  ^
`,
		},
		{
			name: "provider_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  provider           = "some_provider"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:5:3: TF051: Meta block must have an additional newline separating it from the next section.
  disable_on_destroy = true
  ^

test.tf:4:3: TF100: Attribute must be in the meta block at the top of the definition.
  provider           = "some_provider"
  ^
`,
		},
		{
			name: "project_correct_no_meta_block",
			content: `
resource "google_project_service" "run_api" {
  project = "some_project_id"

  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
		},
		{
			name: "project_correct_meta_block",
			content: `
resource "google_project_service" "run_api" {
  for_each = toset(["name"])

  project = "some_project_id"

  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
		},
		{
			name: "project_missing_newline",
			content: `
resource "google_project_service" "run_api" {
  project            = "some_project_id"
  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:4:3: TF050: Provider-specific attributes must have an additional newline separating them from the next section.
  service            = "run.googleapis.com"
  ^
`,
		},
		{
			name: "project_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  project            = "some_project_id"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:5:3: TF050: Provider-specific attributes must have an additional newline separating them from the next section.
  disable_on_destroy = true
  ^

test.tf:4:3: TF101: Attribute must be below any meta attributes (e.g. "for_each", "count") but above all other attributes. Attributes must be ordered organization > folder > project.
  project            = "some_project_id"
  ^
`,
		},
		{
			name: "depends_on_correct",
			content: `
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  disable_on_destroy = true
  depends_on = [
    "something"
  ]
}
				`,
		},
		{
			name: "depends_on_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service = "run.googleapis.com"
  depends_on = [
    "something"
  ]
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:4:3: TF199: Attribute must be at the bottom of the resource definition and in the order "depends_on" then "lifecycle."
  depends_on = [
  ^
`,
		},
		{
			name: "lifecycle_correct",
			content: `
resource "google_project_service" "run_api" {
  service = "run.googleapis.com"
  disable_on_destroy = true
  lifecycle {
    prevent_destroy = true
  }
}
				`,
		},
		{
			name: "lifecycle_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service = "run.googleapis.com"
  lifecycle {
    prevent_destroy = true
  }
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:4:3: TF199: Attribute must be at the bottom of the resource definition and in the order "depends_on" then "lifecycle."
  lifecycle {
  ^
`,
		},
		{
			name: "trailing_mix_correct",
			content: `
resource "google_project_service" "run_api" {
	service = "run.googleapis.com"
	disable_on_destroy = true
	depends_on = [
		"something"
	]
	lifecycle {
		prevent_destroy = true
	}
}
				`,
		},
		{
			name: "trailing_mix_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service = "run.googleapis.com"
  disable_on_destroy = true
  lifecycle {
    prevent_destroy = true
  }
  depends_on = [
    "something"
  ]
}
				`,
			expect: `
test.tf:5:3: TF199: Attribute must be at the bottom of the resource definition and in the order "depends_on" then "lifecycle."
  lifecycle {
  ^

test.tf:8:3: TF199: Attribute must be at the bottom of the resource definition and in the order "depends_on" then "lifecycle."
  depends_on = [
  ^
`,
		},
		{
			name: "source_correct",
			content: `
resource "google_project_service" "run_api" {
  source = "http://somerepo"

  service = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
		},
		{
			name: "source_missing_newline",
			content: `
resource "google_project_service" "run_api" {
  source             = "http://somerepo"
  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:4:3: TF051: Meta block must have an additional newline separating it from the next section.
  service            = "run.googleapis.com"
  ^
`,
		},
		{
			name: "source_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  service            = "run.googleapis.com"
  source             = "http://somerepo"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:5:3: TF051: Meta block must have an additional newline separating it from the next section.
  disable_on_destroy = true
  ^

test.tf:4:3: TF100: Attribute must be in the meta block at the top of the definition.
  source             = "http://somerepo"
  ^
`,
		},
		{
			name: "all_correct",
			content: `
resource "google_project_service" "run_api" {
  for_each = toset(["name"])
  provider = "someprovider"

  organization = "abcxyz"
  folder       = "fid"
  project      = "pid"
  project_id   = "pid"

  service            = "run.googleapis.com"
  disable_on_destroy = true

  depends_on = [
    "something"
  ]

  lifecycle {
    prevent_destroy = true
  }
}
				`,
		},
		{
			name: "mixed_out_of_order",
			content: `
resource "google_project_service" "run_api" {
  folder     = "fid"
  provider   = "someprovider"
  project    = "pid"
  for_each   = toset(["name"])
  project_id = "pid"
  service    = "run.googleapis.com"
  lifecycle {
    prevent_destroy = true
  }
  organization       = "abcxyz"
  disable_on_destroy = true
  depends_on = [
    "something"
  ]
}
				`,
			expect: `
test.tf:8:3: TF050: Provider-specific attributes must have an additional newline separating them from the next section.
  service    = "run.googleapis.com"
  ^

test.tf:5:3: TF051: Meta block must have an additional newline separating it from the next section.
  project    = "pid"
  ^

test.tf:7:3: TF051: Meta block must have an additional newline separating it from the next section.
  project_id = "pid"
  ^

test.tf:4:3: TF100: Attribute must be in the meta block at the top of the definition.
  provider   = "someprovider"
  ^

test.tf:6:3: TF100: Attribute must be in the meta block at the top of the definition.
  for_each   = toset(["name"])
  ^

test.tf:12:3: TF101: Attribute must be below any meta attributes (e.g. "for_each", "count") but above all other attributes. Attributes must be ordered organization > folder > project.
  organization       = "abcxyz"
  ^

test.tf:9:3: TF199: Attribute must be at the bottom of the resource definition and in the order "depends_on" then "lifecycle."
  lifecycle {
  ^
`,
		},
		// Terraform AST treats comments on a line differently than any other token.
		// Comments absorb the newline character instead of treating it as a separate token.
		// This requires us to check for either a true newline token or a comment token
		// that we can treat as the end of the line. See issue #83.
		{
			name: "repro_panic_on_comment_at_end_of_line",
			content: `
resource "a" "b" {
  c = var.d # e
}
			`,
		},
		{
			name: "resource with hyphen in name",
			content: `
resource "google_project_service" "run-api" {
  service            = "run.googleapis.com"
  disable_on_destroy = true
}
				`,
			expect: `
test.tf:2:36: TF001: Resource name must not contain a "-". Prefer underscores ("_") instead.
resource "google_project_service" "run-api" {
                                   ^
`,
		},
		{
			name: "module with hyphen in name",
			content: `
module "my-cool-module" {
  x = "some value"
}
				`,
			expect: `
test.tf:2:9: TF001: Resource name must not contain a "-". Prefer underscores ("_") instead.
module "my-cool-module" {
        ^
`,
		},
		{
			name: "variable with hyphen in name",
			content: `
variable "billing-account" {
  description = "The ID of the billing account to associate projects with"
  type        = string
}
				`,
			expect: `
test.tf:2:11: TF001: Resource name must not contain a "-". Prefer underscores ("_") instead.
variable "billing-account" {
          ^
`,
		},
		{
			name: "output with hyphen in name",
			content: `
output "my-output" {
  value = module.my-output
}
				`,
			expect: `
test.tf:2:9: TF001: Resource name must not contain a "-". Prefer underscores ("_") instead.
output "my-output" {
        ^
`,
		},
		{
			name: "provider_project_at_top",
			content: `
resource "google_project_service" "run_api" {
  project      = "pid"
  folder       = "fid"
  organization = "abcxyz"
}
				`,
			expect: `
test.tf:4:3: TF101: Attribute must be below any meta attributes (e.g. "for_each", "count") but above all other attributes. Attributes must be ordered organization > folder > project.
  folder       = "fid"
  ^

test.tf:5:3: TF101: Attribute must be below any meta attributes (e.g. "for_each", "count") but above all other attributes. Attributes must be ordered organization > folder > project.
  organization = "abcxyz"
  ^
`,
		},
		// Issue #87 - source and for_each are both valid at the top and shouldn't
		// cause violations if both are present.
		{
			name: "for_each_and_source_both_present_repro",
			content: `
module "some_module" {
  source   = "git://https://github.com/abc/def"
  for_each = local.mylocal
}

module "some_module" {
  for_each = local.mylocal
  source   = "git://https://github.com/abc/def"
}
			`,
		},
		{
			// linter is detecting the "module" ident token in the trimprefix call and starting a new
			// block which throws all of the block selection logic into a broken state. This causes it
			// to see the "for_each" in the following resource as being on the wrong line (not at the top)
			// causing a false violation
			name: "special_ident_tokens_in_locals",
			content: `
locals {
  ingestion_backed_client_env_vars = {
    "AUDIT_CLIENT_BACKEND_REMOTE_ADDRESS" : "${trimprefix(module.server_service.audit_log_server_url, "https://")}:443",
    "AUDIT_CLIENT_CONDITION_REGEX_PRINCIPAL_INCLUDE" : ".*",
  }
}

resource "google_cloud_run_service" "ingestion_backend_client_services" {
  for_each = var.client_images
}
			`,
		},
		{
			name: "allows_import_blocks",
			content: `
import {
	to = module.project.google_project.default
	id = "project-id-with-hyphens"
}
			`,
		},
		{
			name: "allows_moved_blocks",
			content: `
moved {
	from = google_bigquery_table_iam_member.editors["serviceAccount:service-123456789@dataflow-service-producer-prod.iam.gserviceaccount.com"]
	to   = module.project.google_bigquery_table_iam_member.editors["serviceAccount:service-123456789@dataflow-service-producer-prod.iam.gserviceaccount.com"]
}
			`,
		},
		// https://github.com/abcxyz/terraform-linter/issues/17
		{
			name: "project_id_attribute_map",
			content: `
module "mymodule" {
  source = "modules/mymodule"

  some_object = {
    folder_id  = "1234"
		project_id = "5678"
  }
}
			`,
		},
		// https://github.com/abcxyz/terraform-linter/issues/30
		{
			name: "bug_repro_hyphen_in_string_value - no support for data blocks",
			content: `
		data "google_project" "gad" {
		  project_id = module.imports.data.action_dispatcher.components.webhook.stage.project_id
		}

		module "common" {
		  domains = ["action-dispatcher-stage.ghss.joonix.net"]
		}
		        `,
			expect: ``,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			linter, err := New(nil)
			if err != nil {
				t.Fatal(err)
			}

			if err := linter.findViolations([]byte(tc.content), "./test.tf"); err != nil {
				t.Fatal(err)
			}

			findings := linter.Findings()

			var buf bytes.Buffer
			for _, finding := range findings {
				fmt.Fprintln(&buf, finding.String())
			}

			if got, want := strings.TrimSpace(buf.String()), strings.TrimSpace(tc.expect); got != want {
				t.Errorf("expected: \n\n%s\n\ngot:\n\n%s", want, got)
			}
		})
	}
}
