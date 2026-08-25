import json
from pathlib import Path
from checker import check_case


class NetSageEngine:
    """
    NetSage AI diagnostic engine.

    IMPORTANT:
    expected_fault is NOT used to generate the diagnosis.
    It is only used later for evaluation.

    Diagnosis is based on:
        - symptom
        - topology_note
        - concept_tag
        - severity
        - show_outputs
        - deterministic checker findings
    """

    def __init__(self):
        self.name = "NetSage AI"
        self.version = "1.0"
    def build_ai_prompt(self, case, findings):
        """
        Build the final diagnostic prompt using the project's
        diagnose_prompt.md template.
        """

        prompt_path = (
            Path(__file__).resolve().parent.parent
            / "prompts"
            / "diagnose_prompt.md"
        )

        template = prompt_path.read_text(
            encoding="utf-8"
        )

        rule_findings = json.dumps(
            findings,
            indent=2
        )

        prompt = template

        replacements = {
            "{case_id}": str(
                case.get("case_id", "")
            ),

            "{symptom}": str(
                case.get("symptom", "")
            ),

            "{topology_note}": str(
                case.get("topology_note", "")
            ),

            "{concept_tag}": str(
                case.get("concept_tag", "")
            ),

            "{severity}": str(
                case.get("severity", "")
            ),

            "{show_outputs}": str(
                case.get("show_outputs", "")
            ),

            "{rule_findings}": rule_findings
        }

        for placeholder, value in replacements.items():

            prompt = prompt.replace(
                placeholder,
                value
            )

        return prompt
    # =========================================================
    # MAIN DIAGNOSIS
    # =========================================================

    def diagnose(self, case):

        checker_result = check_case(case)

        findings = checker_result["findings"]

        root_cause = self.infer_root_cause(
            case,
            findings
        )

        osi_layer = self.infer_osi_layer(
            case,
            findings
        )

        confidence = self.calculate_confidence(
            case,
            findings
        )

        evidence = self.extract_evidence(
            case,
            findings
        )

        next_command = self.select_next_command(
            case,
            findings
        )

        fix_steps = self.generate_fix(
            case,
            findings,
            root_cause
        )

        uncertainty = self.generate_uncertainty(
            findings
        )

        return {
            "case_id": case.get("case_id", "UNKNOWN"),
            "root_cause": root_cause,
            "osi_layer": osi_layer,
            "confidence": confidence,
            "evidence": evidence,
            "next_command": next_command,
            "fix_steps": fix_steps,
            "uncertainty": uncertainty,
            "review_status": "PENDING"
        }

    # =========================================================
    # ROOT CAUSE INFERENCE
    # =========================================================

    def infer_root_cause(self, case, findings):

        # Deterministic evidence has priority.
        if findings:

            highest = self.select_strongest_finding(
                findings
            )

            return highest["message"]

        concept = str(
            case.get("concept_tag", "")
        ).lower()

        symptom = str(
            case.get("symptom", "")
        ).lower()

        show = str(
            case.get("show_outputs", "")
        ).lower()

        # -----------------------------------------------------
        # VLAN
        # -----------------------------------------------------

        if concept == "vlan":

            if "vlan20" in show and "vlan10" in show:

                return (
                    "The affected switch port appears to be "
                    "assigned to the wrong VLAN."
                )

            return (
                "The connectivity problem is likely related "
                "to VLAN membership."
            )

        # -----------------------------------------------------
        # Inter-VLAN Routing
        # -----------------------------------------------------

        if concept == "inter-vlan routing":

            if "encapsulation dot1q" in show:

                return (
                    "The router-on-a-stick subinterface appears "
                    "to use an incorrect VLAN encapsulation."
                )

            if "administratively down" in show:

                return (
                    "The VLAN router subinterface appears "
                    "to be administratively disabled."
                )

            return (
                "The failure is likely related to inter-VLAN "
                "routing configuration."
            )

        # -----------------------------------------------------
        # Trunking
        # -----------------------------------------------------

        if concept == "trunking":

            if "allowed vlans" in show:

                return (
                    "The required VLAN is not included in the "
                    "trunk's allowed VLAN list."
                )

            if "no trunk ports" in show:

                return (
                    "The inter-switch connection is not operating "
                    "as a trunk."
                )

            return (
                "The inter-switch trunk configuration requires "
                "verification."
            )

        # -----------------------------------------------------
        # Switch Port Configuration
        # -----------------------------------------------------

        if concept == "switch port configuration":

            if "switchport mode trunk" in show:

                return (
                    "The endpoint switch port is configured as "
                    "a trunk instead of an access port."
                )

        # -----------------------------------------------------
        # Interface Status
        # -----------------------------------------------------

        if concept == "interface status":

            if "disabled" in show:

                return (
                    "The switch interface connected to the client "
                    "is administratively disabled."
                )

        # -----------------------------------------------------
        # VLAN Database
        # -----------------------------------------------------

        if concept == "vlan database":

            if "absent" in show:

                return (
                    "The required VLAN has not been created "
                    "in the switch VLAN database."
                )

        # -----------------------------------------------------
        # DHCP
        # -----------------------------------------------------

        if concept == "dhcp":

            if "default gateway" in show:

                return (
                    "The DHCP pool is providing an incorrect "
                    "default gateway."
                )

        if concept == "dhcp relay":

            if "no ip helper-address" in show:

                return (
                    "The DHCP relay configuration is missing "
                    "from the client VLAN interface."
                )

            if "incorrect" in show:

                return (
                    "The DHCP relay points to an incorrect "
                    "server address."
                )

        if concept == "dhcp pool":

            return (
                "The DHCP configuration does not contain the "
                "required pool for the affected VLAN."
            )

        if concept == "dhcp exclusion":

            return (
                "The router's gateway address has not been "
                "excluded from the DHCP allocation range."
            )

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        if concept == "dns":

            if "actual dns server" in show:

                return (
                    "The client is configured with an incorrect "
                    "DNS server address."
                )

            if "dns server timeout" in show:

                return (
                    "The configured DNS server is not responding "
                    "to name-resolution requests."
                )

            return (
                "The problem appears to be related to DNS "
                "configuration or name resolution."
            )

        # -----------------------------------------------------
        # Static Routing
        # -----------------------------------------------------

        if concept == "static routing":

            if "no route" in show or "not found" in show:

                return (
                    "The required route to the remote network "
                    "is missing from the routing table."
                )

            if "has no route" in show:

                return (
                    "The router is missing the return route "
                    "to the remote network."
                )

        # -----------------------------------------------------
        # OSPF
        # -----------------------------------------------------

        if concept == "ospf":

            if "not enabled" in show:

                return (
                    "OSPF is not enabled on the required "
                    "interface or network."
                )

            if "hello 10 sec" in show and "hello 30 sec" in show:

                return (
                    "The OSPF hello/dead timer configuration "
                    "does not match between the routers."
                )

        # -----------------------------------------------------
        # ACL
        # -----------------------------------------------------

        if concept == "acl":

            if "deny tcp" in show:

                return (
                    "An ACL deny rule is blocking the required "
                    "TCP traffic."
                )

            if "deny icmp" in show:

                return (
                    "An ACL deny rule is blocking ICMP monitoring "
                    "traffic."
                )

            if "permit ip" in show:

                return (
                    "The ACL currently permits traffic that should "
                    "be restricted between the guest and internal networks."
                )

        # -----------------------------------------------------
        # NAT
        # -----------------------------------------------------

        if concept == "nat":

            if "empty" in show:

                return (
                    "NAT translations are not being created, "
                    "indicating an incorrect NAT inside/outside "
                    "configuration."
                )

        # -----------------------------------------------------
        # PAT
        # -----------------------------------------------------

        if concept == "pat":

            if "vlan20" in show:

                return (
                    "The NAT/PAT access list does not include "
                    "the VLAN20 source network."
                )

        # -----------------------------------------------------
        # Wireless DHCP
        # -----------------------------------------------------

        if concept == "wireless dhcp":

            if "vlan1" in show and "vlan40" in show:

                return (
                    "The access point switch port is connected "
                    "to the wrong VLAN."
                )

        # -----------------------------------------------------
        # Wireless VLAN
        # -----------------------------------------------------

        if concept == "wireless vlan":

            if "access vlan 10" in show and "vlan40" in show:

                return (
                    "The access point switch port is assigned "
                    "to VLAN10 while the wireless network uses VLAN40."
                )

        # -----------------------------------------------------
        # Wireless Security
        # -----------------------------------------------------

        if concept == "wireless security":

            if "client isolation disabled" in show:

                return (
                    "Wireless client isolation is disabled, "
                    "allowing guest clients to communicate with each other."
                )

        # -----------------------------------------------------
        # Wireless Routing
        # -----------------------------------------------------

        if concept == "wireless routing":

            if "no 0.0.0.0/0 route" in show:

                return (
                    "The wireless network has no default route "
                    "toward the ISP."
                )

        # -----------------------------------------------------
        # Generic fallback
        # -----------------------------------------------------

        return (
            "The supplied evidence indicates a configuration "
            "problem in the reported network area, but additional "
            "verification is required to determine the exact root cause."
        )

    # =========================================================
    # OSI LAYER
    # =========================================================

    def infer_osi_layer(self, case, findings):

        # The case contains the expected OSI classification,
        # but the engine does not use expected_fault.
        #
        # For diagnosis, concept_tag and observed evidence
        # determine the layer.

        concept = str(
            case.get("concept_tag", "")
        ).lower()

        if concept in [
            "vlan",
            "trunking",
            "vlan database",
            "switch port configuration",
            "interface status",
            "wireless dhcp",
            "wireless vlan",
            "wireless security"
        ]:
            return "Layer 2"

        if concept in [
            "inter-vlan routing",
            "default gateway",
            "static routing",
            "ospf",
            "nat",
            "pat",
            "wireless routing"
        ]:
            return "Layer 3"

        if concept == "acl":

            show = str(
                case.get("show_outputs", "")
            ).lower()

            if "tcp" in show:
                return "Layer 4"

            return "Layer 3"

        if concept in [
            "dhcp",
            "dhcp relay",
            "dhcp pool",
            "dhcp exclusion",
            "dns"
        ]:
            return "Layer 7"

        return "Unknown"

    # =========================================================
    # CONFIDENCE
    # =========================================================

    def calculate_confidence(self, case, findings):

        if findings:

            high = sum(
                1
                for finding in findings
                if finding["severity"] == "HIGH"
            )

            medium = sum(
                1
                for finding in findings
                if finding["severity"] == "MEDIUM"
            )

            if high >= 1:
                return "High"

            if medium >= 1:
                return "Medium"

        # Evidence exists even without deterministic checker
        # findings, so use a moderate confidence.
        show = str(
            case.get("show_outputs", "")
        ).strip()

        if show:
            return "Medium"

        return "Low"

    # =========================================================
    # EVIDENCE
    # =========================================================

    def extract_evidence(self, case, findings):

        evidence = []

        # First use exact deterministic evidence.
        for finding in findings:

            evidence.append(
                finding["evidence"]
            )

        # If checker found nothing, preserve actual case evidence.
        if not evidence:

            show = str(
                case.get("show_outputs", "")
            )

            if show:
                evidence.append(show)

        return evidence

    # =========================================================
    # NEXT COMMAND
    # =========================================================

    def select_next_command(self, case, findings):

        concept = str(
            case.get("concept_tag", "")
        ).lower()

        commands = {

            "vlan":
                "show vlan brief",

            "inter-vlan routing":
                "show ip interface brief",

            "trunking":
                "show interfaces trunk",

            "vlan database":
                "show vlan brief",

            "switch port configuration":
                "show running-config interface Fa0/7",

            "interface status":
                "show interfaces status",

            "dhcp":
                "show ip dhcp pool",

            "dhcp relay":
                "show running-config interface",

            "dhcp pool":
                "show ip dhcp pool",

            "dhcp exclusion":
                "show ip dhcp binding",

            "dns":
                "ipconfig /all",

            "static routing":
                "show ip route",

            "ospf":
                "show ip ospf neighbor",

            "acl":
                "show access-lists",

            "nat":
                "show ip nat translations",

            "pat":
                "show access-lists",

            "wireless dhcp":
                "show vlan brief",

            "wireless vlan":
                "show running-config interface",

            "wireless security":
                "show wireless client",

            "wireless routing":
                "show ip route"
        }

        if concept in commands:
            return commands[concept]

        if findings:

            return "show running-config"

        return "show running-config"

    # =========================================================
    # FIX STEPS
    # =========================================================

    def generate_fix(
        self,
        case,
        findings,
        root_cause
    ):

        concept = str(
            case.get("concept_tag", "")
        ).lower()

        fixes = {

            "vlan": [
                "Identify the affected switch port.",
                "Enter interface configuration mode.",
                "Assign the port to the intended access VLAN.",
                "Verify VLAN membership.",
                "Test PC-to-PC connectivity."
            ],

            "inter-vlan routing": [
                "Verify the affected router subinterface.",
                "Check the VLAN encapsulation ID.",
                "Verify the subinterface is administratively enabled.",
                "Correct the configuration if required.",
                "Verify inter-VLAN connectivity."
            ],

            "trunking": [
                "Verify the inter-switch interface.",
                "Confirm that the interface operates as a trunk.",
                "Verify the required VLAN is allowed.",
                "Check trunk status.",
                "Test connectivity across the switches."
            ],

            "vlan database": [
                "Create the required VLAN.",
                "Verify that the VLAN appears in the VLAN database.",
                "Assign the required switch ports.",
                "Test connectivity."
            ],

            "switch port configuration": [
                "Identify the endpoint switch port.",
                "Configure the port as an access port.",
                "Assign the intended VLAN.",
                "Verify the interface configuration.",
                "Test connectivity."
            ],

            "interface status": [
                "Verify the affected switch interface.",
                "Enable the interface if it should be active.",
                "Confirm the interface status.",
                "Test client connectivity."
            ],

            "dhcp": [
                "Verify the DHCP pool configuration.",
                "Check the default-router setting.",
                "Correct the gateway address if required.",
                "Renew the client DHCP lease.",
                "Verify connectivity."
            ],

            "dhcp relay": [
                "Verify the client VLAN interface.",
                "Check the ip helper-address configuration.",
                "Correct the DHCP server address if necessary.",
                "Renew the client lease.",
                "Verify DHCP operation."
            ],

            "dhcp pool": [
                "Verify the DHCP pools configured on the router.",
                "Create the missing VLAN DHCP pool.",
                "Configure the correct network and gateway.",
                "Renew the client address.",
                "Verify DHCP operation."
            ],

            "dhcp exclusion": [
                "Identify reserved gateway and infrastructure addresses.",
                "Configure DHCP exclusions.",
                "Verify the DHCP binding table.",
                "Renew affected client leases."
            ],

            "dns": [
                "Verify the DNS server configured on the client.",
                "Compare it with the intended DNS server.",
                "Correct the DNS configuration.",
                "Run nslookup again.",
                "Verify name resolution."
            ],

            "static routing": [
                "Inspect the routing table.",
                "Identify the missing destination network.",
                "Verify the next-hop router.",
                "Configure the required static route.",
                "Verify the route appears in the routing table."
            ],

            "ospf": [
                "Verify OSPF configuration on both routers.",
                "Check the OSPF-enabled interfaces.",
                "Verify the OSPF area.",
                "Verify hello and dead timers.",
                "Check the neighbor relationship again."
            ],

            "acl": [
                "Inspect the complete ACL.",
                "Identify the rule affecting the required traffic.",
                "Verify whether the traffic should be permitted or denied.",
                "Edit the ACL only after human review.",
                "Re-test the affected traffic."
            ],

            "nat": [
                "Verify inside and outside NAT interfaces.",
                "Check the NAT configuration.",
                "Generate test traffic.",
                "Check the NAT translation table.",
                "Verify Internet connectivity."
            ],

            "pat": [
                "Inspect the NAT access list.",
                "Verify that all required VLAN networks are included.",
                "Update the NAT ACL after human review.",
                "Generate test traffic.",
                "Verify translations."
            ],

            "wireless dhcp": [
                "Verify the AP switch-port VLAN.",
                "Confirm the wireless network VLAN.",
                "Correct the VLAN assignment if necessary.",
                "Renew the wireless client address.",
                "Verify connectivity."
            ],

            "wireless vlan": [
                "Verify the SSID-to-VLAN mapping.",
                "Check the AP switch-port VLAN.",
                "Correct the access VLAN if required.",
                "Reconnect the wireless client.",
                "Test gateway connectivity."
            ],

            "wireless security": [
                "Verify the guest wireless security policy.",
                "Enable client isolation.",
                "Reconnect guest clients.",
                "Verify that client-to-client traffic is blocked."
            ],

            "wireless routing": [
                "Inspect the router routing table.",
                "Verify the default route.",
                "Configure the ISP-facing default route if required.",
                "Verify the route appears in the routing table.",
                "Test Internet connectivity."
            ]
        }

        return fixes.get(
            concept,
            [
                "Collect additional network evidence.",
                "Verify the affected configuration.",
                "Make configuration changes only after human review.",
                "Test the network after remediation."
            ]
        )

    # =========================================================
    # UNCERTAINTY
    # =========================================================

    def generate_uncertainty(self, findings):

        if findings:

            return (
                "Deterministic evidence supports this diagnosis, "
                "but the proposed remediation must be reviewed "
                "by a human operator before deployment."
            )

        return (
            "No deterministic rule matched the supplied evidence. "
            "The diagnosis is based on semantic interpretation of "
            "the case and should be verified with the recommended command."
        )

    # =========================================================
    # FINDING PRIORITY
    # =========================================================

    def select_strongest_finding(self, findings):

        priority = {
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }

        return max(
            findings,
            key=lambda finding:
            priority.get(
                finding["severity"],
                0
            )
        )


# =============================================================
# TEST
# =============================================================

if __name__ == "__main__":

    import pandas as pd

    data = pd.read_csv(
        "data/cases.csv"
    )

    case = data.iloc[0].to_dict()

    engine = NetSageEngine()

    checker_result = check_case(
        case
    )

    prompt = engine.build_ai_prompt(
        case,
        checker_result["findings"]
    )

    print("=" * 70)
    print("NETSAGE AI - GENERATED DIAGNOSTIC PROMPT")
    print("=" * 70)

    print(prompt)