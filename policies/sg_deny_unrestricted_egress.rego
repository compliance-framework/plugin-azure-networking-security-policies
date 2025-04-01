package compliance_framework.template.azure._deny_unrestricted_egress

# METADATA
# title: Ensure outbound egress traffic is restricted
# description: Verifies that security groups do not allow unrestricted outbound traffic to the internet, mitigating the risk of data exfiltration.
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
            "6.e", # Ensure outbound traffic restrictions to prevent data exfiltration.
        ],
    },
]

violation[{
  "title": "Egress rules should not allow unrestricted outbound traffic",
  "description": "Outbound traffic should be limited to prevent data exfiltration.",
}] if {
  input.Properties.defaultSecurityRules[_].properties.direction == "Outbound"
  input.Properties.defaultSecurityRules[_].properties.destinationAddressPrefix == "Internet"
}
