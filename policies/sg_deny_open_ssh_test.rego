package compliance_framework.template.azure._deny_open_ssh_test

import data.compliance_framework.template.azure._deny_open_ssh

test_violation_open_ssh if {
  _deny_open_ssh.violation[_] with input as {
    "Properties": {
      "securityRules": [{"properties": {"direction": "Inbound", "destinationPortRange": "22", "sourceAddressPrefix": "0.0.0.0/0"}}]
    }
  }
}
