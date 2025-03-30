# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/aboutcode-org/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/aboutcode-org/scancode.io for support and download.

from django.core.exceptions import ValidationError

import saneyaml

def load_policies_yaml(policies_yaml):
    """Load provided ``policies_yaml``."""
    try:
        return saneyaml.load(policies_yaml)
    except saneyaml.YAMLError as e:
        raise ValidationError(f"Policies file format error: {e}")

def load_policies_file(policies_file, validate=True):
    """
    Load provided ``policies_file`` into a Python dictionary.
    The policies format is validated by default.
    """
    policies_dict = load_policies_yaml(policies_yaml=policies_file.read_text())
    if validate:
        validate_policies(policies_dict)
    return policies_dict

def validate_policies(policies_dict):
    """Return True if the provided ``policies_dict`` is valid."""
    if not isinstance(policies_dict, dict):
        raise ValidationError("The `policies_dict` argument must be a dictionary.")

    if "license_policies" not in policies_dict:
        raise ValidationError(
            "The `license_policies` key is missing from provided policies data."
        )

    if "clarity_policies" in policies_dict:
        validate_clarity_policies(policies_dict["clarity_policies"])

    return True

def validate_clarity_policies(clarity_policies):
    """Validate the clarity policies structure."""
    if not isinstance(clarity_policies, list):
        raise ValidationError("The `clarity_policies` must be a list.")

    for policy in clarity_policies:
        if not isinstance(policy, dict):
            raise ValidationError("Each clarity policy must be a dictionary.")
        if "threshold" not in policy:
            raise ValidationError("Each clarity policy must have a 'threshold' key.")
        if not isinstance(policy["threshold"], (int, float)) or not (0 <= policy["threshold"] <= 100):
            raise ValidationError("Clarity threshold must be a number between 0 and 100.")
        if "compliance_alert" not in policy:
            raise ValidationError("Each clarity policy must have a 'compliance_alert' key.")
        if policy["compliance_alert"] not in ["", "info", "warning", "error"]:
            raise ValidationError("Invalid compliance_alert value in clarity policy.")

def make_license_policy_index(policies_dict):
    """Return an inverted index by ``key`` of the ``policies_list``."""
    validate_policies(policies_dict)

    license_policies = policies_dict.get("license_policies", [])
    return {policy.get("license_key"): policy for policy in license_policies}

def make_clarity_policy_index(policies_dict):
    """Return a sorted list of clarity policies by threshold."""
    validate_policies(policies_dict)

    clarity_policies = policies_dict.get("clarity_policies", [])
    return sorted(clarity_policies, key=lambda x: x["threshold"], reverse=True)
