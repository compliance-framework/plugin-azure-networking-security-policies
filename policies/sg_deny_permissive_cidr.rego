package compliance_framework.template.azure._deny_permissive_cidr

# METADATA
# title: Ensure security groups do not allow overly permissive IP ranges
# description: Identifies security group rules with overly permissive source address prefixes, such as '0.0.0.0/0', which can increase exposure to potential threats.
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
