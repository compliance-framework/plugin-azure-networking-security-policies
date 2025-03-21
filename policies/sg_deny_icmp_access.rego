package compliance_framework.template.azure._deny_icmp_access

violation[{
  "title": "ICMP access should be restricted",
  "description": "Security group allows unrestricted ICMP traffic, which may pose a security risk.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
  input.Properties.securityRules[_].properties.protocol == "icmp"
}
