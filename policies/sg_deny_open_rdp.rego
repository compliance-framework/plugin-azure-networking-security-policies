package compliance_framework.template.azure._deny_open_rdp

violation[{
  "title": "RDP (port 3389) should not be open to the world",
  "description": "Security group allows unrestricted RDP access, which increases the attack surface.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
  input.Properties.securityRules[_].properties.destinationPortRange == "3389"
}