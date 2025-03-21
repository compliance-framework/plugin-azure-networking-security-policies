package compliance_framework.template.azure._deny_open_rdp_test

import data.compliance_framework.template.azure._deny_open_rdp

test_violation_open_rdp if {
  _deny_open_rdp.violation[_] with input as {
    "Properties": {
      "securityRules": [{"properties": {"direction": "Inbound", "destinationPortRange": "3389", "sourceAddressPrefix": "0.0.0.0/0"}}]
    }
  }
}
