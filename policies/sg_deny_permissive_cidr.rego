package compliance_framework.template.azure._deny_permissive_cidr

violation[{
  "title": "CIDR block is too permissive",
  "description": "Security group allows overly broad IP ranges, increasing exposure.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
}

violation[{
  "title": "CIDR block is too permissive",
  "description": "Security group allows overly broad IP ranges, increasing exposure.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/1"
}

violation[{
  "title": "CIDR block is too permissive",
  "description": "Security group allows overly broad IP ranges, increasing exposure.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/2"
}
