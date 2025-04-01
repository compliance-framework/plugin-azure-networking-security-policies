package compliance_framework.template.azure._deny_open_ssh

# METADATA
# title: Ensure SSH (port 22) is not open to the internet
# description: Verifies that security groups do not allow unrestricted SSH access from the internet to maintain system security and integrity.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    # https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/Cyber%20Security%20Framework.pdf
    # Class: SAMA_CSF_1.0
    #
    # 3.3.5: Identity and Access Management
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.5", # Identity and Access Management
        "statement-ids": [
            "2", # Ensure proper identification and access control mechanisms.
        ],
    },
    # 3.3.8: Infrastructure Security
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.8", # Infrastructure Security
        "statement-ids": [
            "6.c", # Ensure that security controls are implemented to protect the network infrastructure.
        ],
    },
]

violation[{
  "title": "SSH (port 22) should not be open to the world",
  "description": "Security group allows SSH access (port 22) from 0.0.0.0/0, which poses a security risk.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
  input.Properties.securityRules[_].properties.destinationPortRange == "22"
}
