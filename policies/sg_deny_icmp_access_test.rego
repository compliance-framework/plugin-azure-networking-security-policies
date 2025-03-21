package compliance_framework.template.azure._deny_icmp_access_test

import data.compliance_framework.template.azure._deny_icmp_access

test_violation_icmp_access if {
  _deny_icmp_access.violation[_] with input as {
    "Properties": {
      "securityRules": [{"properties": {"direction": "Inbound", "sourceAddressPrefix": "0.0.0.0/0", "protocol": "icmp"}}]
    }
  }
}
