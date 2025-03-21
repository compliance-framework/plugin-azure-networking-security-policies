package compliance_framework.template.azure._deny_open_database_ports_test

import data.compliance_framework.template.azure._deny_open_database_ports

test_violation_open_database_ports if {
  _deny_open_database_ports.violation[_] with input as {
    "Properties": {
      "securityRules": [{"properties": {"direction": "Inbound", "destinationPortRange": "3306", "sourceAddressPrefix": "0.0.0.0/0"}}]
    }
  }
}