package compliance_framework.template.azure._deny_open_ssh

violation[{
  "title": "SSH (port 22) should not be open to the world",
  "description": "Security group allows SSH access (port 22) from 0.0.0.0/0, which poses a security risk.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
  input.Properties.securityRules[_].properties.destinationPortRange == "22"
}
