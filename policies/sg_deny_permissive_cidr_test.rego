package compliance_framework.template.azure._deny_permissive_cidr_test

import data.compliance_framework.template.azure._deny_permissive_cidr

test_violation_permissive_cidr if {
  _deny_permissive_cidr.violation[_] with input as {
    "Properties": {
      "securityRules": [{"properties": {"sourceAddressPrefix": "0.0.0.0/0"}}]
    }
  }
}

test_violation_permissive_cidr_2 if {
  _deny_permissive_cidr.violation[_] with input as {
    "Properties": {
      "securityRules": [{"properties": {"sourceAddressPrefix": "0.0.0.0/1"}}]
    }
  }
}

test_violation_permissive_cidr_3 if {
  _deny_permissive_cidr.violation[_] with input as {
    "Properties": {
      "securityRules": [{"properties": {"sourceAddressPrefix": "0.0.0.0/2"}}]
    }
  }
}
