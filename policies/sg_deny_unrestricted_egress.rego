package compliance_framework.template.azure._deny_unrestricted_egress

default disallow_traffic = false

disallow_traffic if {
  some item in input.Properties.securityRules
  item.properties.access == "Deny"
  item.properties.direction == "Outbound"
  item.properties.destinationAddressPrefix == "*"
  item.properties.destinationPortRange == "*"
  item.properties.priority < 65000
}

violation[{
  "title": "Egress rules should not allow unrestricted outbound traffic",
  "description": "Outbound traffic should be limited to prevent data exfiltration.",
}] if {
    not disallow_traffic
}
