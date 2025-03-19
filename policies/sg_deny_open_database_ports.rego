package compliance_framework.template.azure._deny_open_database_ports

db_ports := {"3306", "5432", "1433"}

violation[{
  "title": sprintf("Database port %s should not be open to the world", [input.Properties.securityRules[_].properties.destinationPortRange]),
  "description": "Publicly accessible database increases the risk of data exposure.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
  db_ports[input.Properties.securityRules[_].properties.destinationPortRange]
}
