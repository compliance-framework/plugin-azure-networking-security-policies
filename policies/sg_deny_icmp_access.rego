package compliance_framework.template.azure._deny_icmp_access

# METADATA
# title: Ensure security groups restrict ICMP access from the internet
# description: Verifies that security groups do not allow unrestricted ICMP traffic from the internet to maintain network security and integrity.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#   schedule: "* * * * * *"

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

violation[{
  "title": "ICMP access should be restricted",
  "description": "Security group allows unrestricted ICMP traffic, which may pose a security risk.",
}] if {
  input.Properties.securityRules[_].properties.sourceAddressPrefix == "0.0.0.0/0"
  input.Properties.securityRules[_].properties.protocol == "icmp"
}
