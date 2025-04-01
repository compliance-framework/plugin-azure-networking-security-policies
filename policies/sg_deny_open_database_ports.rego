package compliance_framework.template.azure._deny_open_database_ports

# METADATA
# title: Ensure database ports are not open to the internet
# description: Verifies that security groups do not allow unrestricted access to database ports from the internet to maintain data security and integrity.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#   schedule: "* * * * * *"

db_ports := {"3306", "5432", "1433"}

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf
    # Class: SAMA_CSF_1.0
    #
    # 3.3.8: Infrastructure Security
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.8", # Infrastructure Security
        "statement-ids": [
            "6.c", # Ensure that security controls are implemented to protect the network infrastructure.
        ],
    },
]

db_ports := {"3306", "5432", "1433"}

violation[{
  "title": sprintf("Database port %s should not be open to the world", [input.Properties.securityRules[_].properties.destinationPortRange]),
  "description": "Publicly accessible database increases the risk of data exposure.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
  db_ports[input.Properties.securityRules[_].properties.destinationPortRange]
}
