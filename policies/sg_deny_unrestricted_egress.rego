package compliance_framework.template.azure._deny_unrestricted_egress

violation[{
  "title": "Egress rules should not allow unrestricted outbound traffic",
  "description": "Outbound traffic should be limited to prevent data exfiltration.",
}] if {
  input.Properties.defaultSecurityRules[_].properties.direction == "Outbound"
  input.Properties.defaultSecurityRules[_].properties.destinationAddressPrefix == "Internet"
}
