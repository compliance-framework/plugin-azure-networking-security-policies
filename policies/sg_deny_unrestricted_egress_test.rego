package compliance_framework.template.azure._deny_unrestricted_egress_test

import data.compliance_framework.template.azure._deny_unrestricted_egress

test_violation_unrestricted_egress if {
  _deny_unrestricted_egress.violation[_] with input as {
    "Properties": {
      "securityRules": []
    }
  }
}

default disallow_traffic = false

disallow_traffic if {
  _deny_unrestricted_egress.violation[_] with input as {
    "Properties": {
      "securityRules": [
        {
          "properties": {
            "access": "Deny",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "*",
            "direction": "Outbound",
            "priority": 1000
          }
        },
        {
          "properties": {
            "access": "Allow",
            "destinationAddressPrefix": "*",
            "destinationPortRange": "*",
            "direction": "Inbound",
            "priority": 2000
          }
        }
      ]
    }
  }
}

test_no_violation_if_restricted_rule if {
  not disallow_traffic
}
