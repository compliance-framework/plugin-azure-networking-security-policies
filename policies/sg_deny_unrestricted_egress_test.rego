package compliance_framework.template.azure._deny_unrestricted_egress_test

import data.compliance_framework.template.azure._deny_unrestricted_egress

test_violation_unrestricted_egress if {
  _deny_unrestricted_egress.violation[_] with input as {
    "Properties": {
      "securityRules": [],
      "defaultSecurityRules": [{"properties": {"direction": "Outbound", "destinationAddressPrefix": "Internet"}}]
    }
  }
}