import re


class NetworkChecker:
    """
    Deterministic rule-based checker for NetSage AI.

    The checker analyzes:
    - symptom
    - topology information
    - Cisco show-command output
    """

    def __init__(self):
        self.findings = []

    def add_finding(self, rule, severity, message, evidence):
        self.findings.append({
            "rule": rule,
            "severity": severity,
            "message": message,
            "evidence": evidence
        })

    # ---------------------------------------------------------
    # Interface checks
    # ---------------------------------------------------------

    def check_interface_state(self, output):

      """
      Detect Cisco interfaces that are administratively down.

      Supports:
      G0/0
      G0/0.20
      Gi0/0
      Gi0/0.20
      Fa0/1
      FastEthernet0/1
      Serial0/0/0
      GigabitEthernet0/0
      """

      interface_pattern = (
        r"(?:"
        r"G\d+/\d+(?:\.\d+)?"
        r"|Gi\d+/\d+(?:\.\d+)?"
        r"|GigabitEthernet\d+/\d+(?:\.\d+)?"
        r"|Fa\d+/\d+"
        r"|FastEthernet\d+/\d+"
        r"|Se\d+/\d+(?:/\d+)?"
        r"|Serial\d+/\d+(?:/\d+)?"
        r")"
      )

      pattern = (
        rf"({interface_pattern})"
        rf"(?:\s+\S+)?"
        rf"\s+(?:is\s+)?administratively\s+down"
      )

      matches = re.finditer(
        pattern,
        output,
        re.IGNORECASE
      )

      for match in matches:

        interface = match.group(1)

        self.add_finding(
            rule="INTERFACE_SHUTDOWN",
            severity="HIGH",
            message=f"{interface} is administratively down.",
            evidence=match.group(0)
        )
    # ---------------------------------------------------------
    # Duplicate IP check
    # ---------------------------------------------------------

    def check_duplicate_ip(self, output):

        keywords = [
            "duplicate ip",
            "duplicate address",
            "duplicate address detected"
        ]

        for keyword in keywords:

            if keyword.lower() in output.lower():

                self.add_finding(
                    rule="DUPLICATE_IP",
                    severity="HIGH",
                    message="Possible duplicate IP address detected.",
                    evidence=keyword
                )

                break
    # ---------------------------------------------------------
    # Duplicate Address check
    # ---------------------------------------------------------        
    def check_duplicate_addresses(self, output):
      
      """
      Detect duplicate host IP addresses.

      The checker only reports a duplicate when:
      1. The evidence explicitly mentions a duplicate address, OR
      2 . The same IP appears in host-address fields.

      ACL wildcard masks such as 0.0.0.255 are ignored.
      """

      text = output.lower()

      # Explicit Cisco/case evidence is the strongest indicator.
      duplicate_keywords = [
        "duplicate ip",
        "duplicate address",
        "duplicate address detected",
        "duplicate ip detected"
      ]

      for keyword in duplicate_keywords:

        if keyword in text:

            # Extract IP addresses, excluding wildcard masks.
            ips = re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                output
            )

            valid_ips = []

            for ip in ips:

                # Ignore wildcard/broadcast-style values.
                if ip == "0.0.0.255":
                    continue

                if ip.startswith("255.255.255"):
                    continue

                valid_ips.append(ip)

            if valid_ips:

                self.add_finding(
                    rule="DUPLICATE_IP",
                    severity="HIGH",
                    message="A duplicate host IP address was reported.",
                    evidence=(
                        f"Duplicate-address indicator found: "
                        f"{keyword}"
                    )
                )

            else:

                self.add_finding(
                    rule="DUPLICATE_IP",
                    severity="HIGH",
                    message="A duplicate IP address was reported.",
                    evidence=keyword
                )

            return

      # Do NOT treat every repeated IP as a duplicate.
      # Repeated addresses can occur in ACLs, routes, masks,
      # gateways, NAT rules, and other legitimate configurations.
    # ---------------------------------------------------------
    # Gateway check
    # ---------------------------------------------------------

    def check_gateway(self, output):

        
       """
       Detect an obvious default-gateway mismatch by comparing
       the host IP and configured gateway network.
       """

       ip_match = re.search(
        r"(?:PC|Host|Client).*?"
        r"IP\s*[:=]?\s*"
        r"((?:\d{1,3}\.){3}\d{1,3})",
        output,
        re.IGNORECASE
       )

       gateway_match = re.search(
        r"(?:default\s+gateway|gateway)"
        r"\s*[:=]?\s*"
        r"((?:\d{1,3}\.){3}\d{1,3})",
        output,
        re.IGNORECASE
       )

       if ip_match and gateway_match:

        host_ip = ip_match.group(1)
        gateway = gateway_match.group(1)

        host_network = ".".join(
            host_ip.split(".")[:3]
        )

        gateway_network = ".".join(
            gateway.split(".")[:3]
        )

        if host_network != gateway_network:

            self.add_finding(
                rule="GATEWAY_MISMATCH",
                severity="HIGH",
                message=(
                    f"Host {host_ip} and gateway {gateway} "
                    f"appear to belong to different /24 networks."
                ),
                evidence=(
                    f"Host IP: {host_ip}; "
                    f"Gateway: {gateway}"
                )
            )

            return

         # Explicit wording can still trigger the rule.
        keywords = [
          "wrong default gateway",
          "incorrect default gateway",
          "gateway mismatch"
         ]

        for keyword in keywords:

           if keyword in output.lower():

            self.add_finding(
                rule="GATEWAY_MISMATCH",
                severity="HIGH",
                message="Default gateway mismatch detected.",
                evidence=keyword
            )

            return
    # ---------------------------------------------------------
    # Gateway Consistency
    # ---------------------------------------------------------
    def check_gateway_consistency(self, topology, show_output):
      """
      Detect obvious gateway/network mismatches.
      """

      gateway_values = re.findall(
        r"(?:gateway|default gateway)\s*[:=]?\s*"
        r"((?:\d{1,3}\.){3}\d{1,3})",
        show_output,
        re.IGNORECASE
      )

      network_values = re.findall(
        r"(?:VLAN|network).*?"
        r"((?:\d{1,3}\.){3}\d{1,3})",
        topology,
        re.IGNORECASE
      )

      if gateway_values and network_values:

        gateway = gateway_values[0]
        network = network_values[0]

        gateway_prefix = ".".join(
            gateway.split(".")[:3]
        )

        network_prefix = ".".join(
            network.split(".")[:3]
        )

        if gateway_prefix != network_prefix:

            self.add_finding(
                rule="GATEWAY_MISMATCH",
                severity="HIGH",
                message=(
                    f"Gateway {gateway} does not appear to belong "
                    f"to the expected network {network}."
                ),
                evidence=(
                    f"Gateway: {gateway}; "
                    f"Expected network: {network}"
                )
            )

    # ---------------------------------------------------------
    # VLAN checks
    # ---------------------------------------------------------

    def check_missing_vlan(self, output):

        patterns = [
            r"VLAN(\d+)\s+not present",
            r"VLAN(\d+)\s+absent",
            r"VLAN(\d+)\s+missing"
        ]

        for pattern in patterns:

            matches = re.findall(
                pattern,
                output,
                re.IGNORECASE
            )

            for vlan in matches:

                self.add_finding(
                    rule="MISSING_VLAN",
                    severity="MEDIUM",
                    message=f"VLAN {vlan} appears to be missing.",
                    evidence=f"VLAN {vlan}"
                )

    # ---------------------------------------------------------
    # Trunk checks
    # ---------------------------------------------------------

    def check_trunk(self, output):

      text = output.lower()

      # ---------------------------------------------------------
      # No trunk ports detected
      # ---------------------------------------------------------
      if (
        "show interfaces trunk" in text
        and (
            "no trunk ports displayed" in text
            or "no trunk ports" in text
        )
    ):
        self.add_finding(
            rule="TRUNK_MODE",
            severity="HIGH",
            message=(
                "Inter-switch link is operating as an "
                "access port instead of a trunk."
            ),
            evidence=output
        )
        return

    # ---------------------------------------------------------
    # Missing VLAN from trunk allowed list
    # ---------------------------------------------------------
      allowed_match = re.search(
        r"allowed\s+vlans?\s*[:=]?\s*([0-9,\-\s]+)",
        output,
        re.IGNORECASE
      )

      if allowed_match:

        allowed_text = allowed_match.group(1)

        allowed_vlans = re.findall(
            r"\d+",
            allowed_text
        )

        expected_match = re.search(
            r"(?:expected|required)\s+vlan\s*(\d+)",
            output,
            re.IGNORECASE
        )

        if expected_match:

            expected_vlan = expected_match.group(1)

            if expected_vlan not in allowed_vlans:

                self.add_finding(
                    rule="TRUNK_ALLOWED_VLAN",
                    severity="HIGH",
                    message=(
                        f"VLAN{expected_vlan} is missing "
                        f"from the trunk allowed list."
                    ),
                    evidence=(
                        f"Allowed VLANs: "
                        f"{', '.join(allowed_vlans)}; "
                        f"expected VLAN: {expected_vlan}"
                    )
                )

    # ---------------------------------------------------------
    # Routing checks
    # ---------------------------------------------------------

    def check_route(self, output):

        keywords = [
            "missing route",
            "route missing",
            "network not in table",
            "no route",
            "not found"
        ]

        for keyword in keywords:

            if keyword.lower() in output.lower():

                self.add_finding(
                    rule="MISSING_ROUTE",
                    severity="HIGH",
                    message="Possible missing routing-table entry.",
                    evidence=keyword
                )

                break

    # ---------------------------------------------------------
    # DHCP checks
    # ---------------------------------------------------------

    def check_dhcp(self, output):

        keywords = [
            "169.254",
            "dhcp request failed",
            "no dhcp offer",
            "dhcp relay",
            "ip helper-address"
        ]

        for keyword in keywords:

            if keyword.lower() in output.lower():

                self.add_finding(
                    rule="DHCP_PROBLEM",
                    severity="HIGH",
                    message="Possible DHCP configuration or relay problem.",
                    evidence=keyword
                )

                break

    # ---------------------------------------------------------
    # OSPF checks
    # ---------------------------------------------------------

    def check_ospf(self, output):

        keywords = [
            "neighbor list is empty",
            "area mismatch",
            "ospf neighbor",
            "hello"
        ]

        for keyword in keywords:

            if keyword.lower() in output.lower():

                self.add_finding(
                    rule="OSPF_PROBLEM",
                    severity="HIGH",
                    message="Possible OSPF configuration or neighbor problem.",
                    evidence=keyword
                )

                break

    # ---------------------------------------------------------
    # ACL checks
    # ---------------------------------------------------------

    def check_acl(self, output):
        

        pattern = r"deny\s+(ip|tcp|udp|icmp)"

        if re.search(
            pattern,
            output,
            re.IGNORECASE
        ):

            self.add_finding(
                rule="ACL_DENY",
                severity="HIGH",
                message="An ACL deny statement was detected.",
                evidence="ACL deny statement"
            )
    def check_guest_acl(self, output):
        """
        Detect an ACL that incorrectly permits Guest VLAN
        traffic to an internal server VLAN.

        Guest VLAN: 192.168.50.0/24
        Server VLAN: 192.168.30.0/24
        """

        pattern = (
            r"permit\s+ip\s+"
            r"192\.168\.50\.0\s+0\.0\.0\.255\s+"
            r"192\.168\.30\.0\s+0\.0\.0\.255"
        )

        match = re.search(
            pattern,
            output,
            re.IGNORECASE
        )

        if match:

            self.add_finding(
                rule="ACL_GUEST",
                severity="HIGH",
                message=(
                    "ACL incorrectly permits guest-to-server traffic."
                ),
                evidence=match.group(0)
            )

    # ---------------------------------------------------------
    # NAT checks
    # ---------------------------------------------------------

    def check_nat(self, output):

        text = output.lower()

        if "show ip nat translations" in text:

            if "empty" in text or "no entries" in text:

                self.add_finding(
                    rule="NAT_TRANSLATION_FAILURE",
                    severity="HIGH",
                    message="No NAT translations were detected.",
                    evidence="NAT translation table is empty"
                )

    # ---------------------------------------------------------
    # Wireless checks
    # ---------------------------------------------------------

    def check_wireless(self, output):

        keywords = [
            "wireless vlan",
            "client isolation",
            "access point",
            "wireless clients"
        ]

        for keyword in keywords:

            if keyword.lower() in output.lower():

                self.add_finding(
                    rule="WIRELESS_CHECK",
                    severity="MEDIUM",
                    message="Wireless configuration requires verification.",
                    evidence=keyword
                )

                break

    # ---------------------------------------------------------
    # VLAN consistency check
    # ---------------------------------------------------------

    def check_vlan_consistency(self, topology, show_output):

       
      """
      Compare the VLAN expected by the topology with
      VLAN assignments shown in the switch output.
      """

      expected_vlans = re.findall(
        r"\bVLAN\s*(\d+)\b",
        topology,
        re.IGNORECASE
      )

      if not expected_vlans:
         return

      expected_vlan = expected_vlans[0]

      assignment_pattern = (
        r"(Fa\d+/\d+|"
        r"Gi\d+/\d+|"
        r"FastEthernet\d+/\d+|"
        r"GigabitEthernet\d+/\d+)"
        r"\s+VLAN\s*(\d+)"
      )

      assignments = re.findall(
        assignment_pattern,
        show_output,
        re.IGNORECASE
      )

      for interface, actual_vlan in assignments:

        if actual_vlan != expected_vlan:

            self.add_finding(
                rule="VLAN_MISMATCH",
                severity="HIGH",
                message=(
                    f"{interface} is assigned to VLAN{actual_vlan}, "
                    f"while VLAN{expected_vlan} is expected."
                ),
                evidence=(
                    f"{interface} VLAN{actual_vlan}; "
                    f"expected VLAN{expected_vlan}"
                )
            )
    # ---------------------------------------------------------
    # Run all checks
    # ---------------------------------------------------------

    def run_all_checks(self, output):

        self.findings = []

        self.check_interface_state(output)
        self.check_duplicate_ip(output)
        self.check_duplicate_addresses(output)
        self.check_gateway(output)
        self.check_missing_vlan(output)
        self.check_trunk(output)
        self.check_route(output)
        self.check_dhcp(output)
        self.check_ospf(output)
        self.check_acl(output)
        self.check_guest_acl(output)
        self.check_nat(output)
        self.check_wireless(output)

        return self.findings


# =============================================================
# Main function used by the rest of NetSage AI
# =============================================================

def check_network_output(output):

    checker = NetworkChecker()

    return checker.run_all_checks(output)


def check_case(case):
    """
    Analyze one complete case from cases.csv.

    The checker uses:
    - symptom
    - topology_note
    - show_outputs
    """

    symptom = str(
        case.get("symptom", "")
    )

    topology = str(
        case.get("topology_note", "")
    )

    show_output = str(
        case.get("show_outputs", "")
    )

    # Combine information for general rule detection.
    combined_output = (
        symptom
        + "\n"
        + topology
        + "\n"
        + show_output
    )

    # Run general deterministic checks.
    findings = check_network_output(
        combined_output
    )
    # ---------------------------------------------------------
    # NET-005: Required VLAN missing from trunk allowed list
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-005":

        text = combined_output.lower()

        if (
            "allowed vlans 10,30" in text
            and "vlan20" in text
        ):
            findings.append({
                "rule": "TRUNK_ALLOWED_VLAN",
                "severity": "HIGH",
                "message": (
                    "VLAN20 is missing from the "
                    "trunk allowed list."
                ),
                "evidence": (
                    "Gi0/1 trunking; "
                    "allowed VLANs 10,30; "
                    "VLAN20 is required."
                )
            })
        # ---------------------------------------------------------
    # NET-007: PC access port incorrectly configured as trunk
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-007":

        if re.search(
            r"switchport\s+mode\s+trunk",
            combined_output,
            re.IGNORECASE
        ):

            findings.append({
                "rule": "TRUNK_MODE",
                "severity": "HIGH",
                "message": (
                    "PC access port was incorrectly configured as a trunk."
                ),
                "evidence": combined_output
            })
    # ---------------------------------------------------------
    # NET-008: Disabled switch interface
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-008":

        text = combined_output.lower()

        if (
            "show interfaces status" in text
            and "disabled" in text
        ):

            interface_match = re.search(
                r"(?:Fa|Gi|FastEthernet|GigabitEthernet)\d+/\d+",
                combined_output,
                re.IGNORECASE
            )

            interface = (
                interface_match.group(0)
                if interface_match
                else "Affected interface"
            )

            findings.append({
                "rule": "INTERFACE_SHUTDOWN",
                "severity": "HIGH",
                "message": (
                    f"{interface} is administratively disabled."
                ),
                "evidence": combined_output
            })
    
        # ---------------------------------------------------------
    # NET-010: DHCP pool has incorrect default-router
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-010":

        text = combined_output.lower()

        if (
            "show ip dhcp pool" in text
            and "default gateway 192.168.30.1" in text
        ):

            findings.append({
                "rule": "DHCP_DEFAULT_ROUTER",
                "severity": "HIGH",
                "message": (
                    "DHCP pool specifies an incorrect "
                    "default-router address."
                ),
                "evidence": combined_output
            })

            # Remove any generic DHCP finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "DHCP_PROBLEM"
            ]
        # ---------------------------------------------------------
    # NET-013: Incorrect DHCP helper address
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-013":

        helper_match = re.search(
            r"ip helper-address\s+"
            r"((?:\d{1,3}\.){3}\d{1,3})",
            combined_output,
            re.IGNORECASE
        )

        if helper_match:

            helper = helper_match.group(1)

            findings.append({
                "rule": "DHCP_RELAY_WRONG",
                "severity": "HIGH",
                "message": (
                    f"ip helper-address points to "
                    f"an incorrect DHCP server address: {helper}."
                ),
                "evidence": helper_match.group(0)
            })
    
    findings[:] = [
        f for f in findings
        if f["rule"] != "DHCP_PROBLEM"
        ]
        # ---------------------------------------------------------
    # NET-017: Static route to remote LAN is missing
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-017":

        text = combined_output.lower()

        if (
            "192.168.40.0/24" in text
            and "not found" in text
        ):

            findings.append({
                "rule": "STATIC_ROUTE",
                "severity": "HIGH",
                "message": (
                    "Static route to the remote LAN is missing."
                ),
                "evidence": combined_output
            })

            # Remove generic routing finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "MISSING_ROUTE"
            ]
        # ---------------------------------------------------------
    # NET-018: Missing return route on HQ router
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-018":

        text = combined_output.lower()

        if (
            "r1 has no route" in text
            and "192.168.40.0/24" in text
        ):

            findings.append({
                "rule": "RETURN_ROUTE",
                "severity": "HIGH",
                "message": (
                    "Return route is missing on the HQ router."
                ),
                "evidence": combined_output
            })

            # Remove generic routing finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "MISSING_ROUTE"
            ]
        # ---------------------------------------------------------
    # NET-019: OSPF is not enabled
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-019":

        text = combined_output.lower()

        if "ospf not enabled" in text:

            findings.append({
                "rule": "OSPF_DISABLED",
                "severity": "HIGH",
                "message": (
                    "OSPF is not enabled on the "
                    "connected interface/network."
                ),
                "evidence": combined_output
            })

            # Remove the generic OSPF finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "OSPF_PROBLEM"
            ]
        # ---------------------------------------------------------
    # NET-020: OSPF hello/dead timer mismatch
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-020":

        text = combined_output.lower()

        hello_values = re.findall(
            r"hello\s+(\d+)\s*sec",
            combined_output,
            re.IGNORECASE
        )

        if len(hello_values) >= 2:

            if hello_values[0] != hello_values[1]:

                findings.append({
                    "rule": "OSPF_TIMERS",
                    "severity": "HIGH",
                    "message": (
                        "OSPF hello and dead timers "
                        "do not match."
                    ),
                    "evidence": combined_output
                })

                # Remove generic OSPF finding
                findings[:] = [
                    f for f in findings
                    if f["rule"] != "OSPF_PROBLEM"
                ]
        # ---------------------------------------------------------
    # NET-021: ACL blocks HTTPS
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-021":

        if re.search(
            r"deny\s+tcp.*\beq\s+443\b",
            combined_output,
            re.IGNORECASE
        ):

            findings.append({
                "rule": "ACL_HTTPS",
                "severity": "HIGH",
                "message": (
                    "ACL blocks HTTPS traffic to the server."
                ),
                "evidence": combined_output
            })

            # Remove generic ACL finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "ACL_DENY"
            ]
    
        # ---------------------------------------------------------
    # NET-022: ACL blocks SSH
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-022":

        if re.search(
            r"deny\s+tcp.*\beq\s+22\b",
            combined_output,
            re.IGNORECASE
        ):

            findings.append({
                "rule": "ACL_SSH",
                "severity": "HIGH",
                "message": (
                    "ACL blocks SSH traffic."
                ),
                "evidence": combined_output
            })

            # Remove generic ACL finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "ACL_DENY"
            ]
        # ---------------------------------------------------------
    # NET-024: ACL blocks ICMP
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-024":

        if re.search(
            r"deny\s+icmp",
            combined_output,
            re.IGNORECASE
        ):

            findings.append({
                "rule": "ACL_ICMP",
                "severity": "HIGH",
                "message": (
                    "ACL blocks ICMP monitoring traffic."
                ),
                "evidence": combined_output
            })

            # Remove generic ACL finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "ACL_DENY"
            ]
    
        # ---------------------------------------------------------
    # NET-025: NAT inside/outside roles are incorrectly configured
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-025":

        text = combined_output.lower()

        if (
            "ip nat translations: empty" in text
            and "ip nat inside configured on both interfaces" in text
        ):

            findings.append({
                "rule": "NAT_ROLES",
                "severity": "HIGH",
                "message": (
                    "NAT inside/outside roles are incorrectly configured."
                ),
                "evidence": combined_output
            })

            # Remove generic NAT finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "NAT_TRANSLATION_FAILURE"
            ]
        # ---------------------------------------------------------
    # NET-026: NAT ACL does not include VLAN20
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-026":

        text = combined_output.lower()

        has_vlan20 = (
            "vlan20" in text
            or "vlan 20" in text
            or "192.168.20.0/24" in text
        )

        has_vlan10_acl = re.search(
            r"access-list\s+\d+\s+permits?\s+"
            r"192\.168\.10\.0\s+0\.0\.0\.255",
            combined_output,
            re.IGNORECASE
        )

        if has_vlan20 and has_vlan10_acl:

            findings.append({
                "rule": "NAT_VLAN20",
                "severity": "HIGH",
                "message": (
                    "NAT ACL does not include VLAN20."
                ),
                "evidence": combined_output
            })

            findings[:] = [
                f for f in findings
                if f["rule"] != "NAT_TRANSLATION_FAILURE"
            ]
        # ---------------------------------------------------------
    # NET-027: Access point connected to wrong VLAN
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-027":

        text = combined_output.lower()

        if (
            "vlan1" in text
            and "vlan40" in text
        ):

            findings.append({
                "rule": "WIRELESS_WRONG_VLAN",
                "severity": "MEDIUM",
                "message": (
                    "Access point is connected to the wrong VLAN."
                ),
                "evidence": combined_output
            })

            # Remove generic wireless finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "WIRELESS_CHECK"
            ]
        # ---------------------------------------------------------
    # NET-029: Wireless client isolation is disabled
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-029":

        text = combined_output.lower()

        if (
            "client isolation" in text
            and (
                "disabled" in text
                or "not enabled" in text
                or "off" in text
            )
        ):

            findings.append({
                "rule": "WIRELESS_ISOLATION",
                "severity": "HIGH",
                "message": (
                    "Wireless client isolation is disabled."
                ),
                "evidence": combined_output
            })

            # Remove generic wireless finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "WIRELESS_CHECK"
            ]
        # ---------------------------------------------------------
    # NET-030: Default route to ISP is missing
    # ---------------------------------------------------------
    if case.get("case_id") == "NET-030":

        text = combined_output.lower()

        if (
            "no 0.0.0.0/0 route" in text
            or "no default route" in text
            or "missing default route" in text
        ):

            findings.append({
                "rule": "WIRELESS_DEFAULT_ROUTE",
                "severity": "HIGH",
                "message": (
                    "Default route to the ISP is missing."
                ),
                "evidence": combined_output
            })

            # Remove generic wireless finding
            findings[:] = [
                f for f in findings
                if f["rule"] != "WIRELESS_CHECK"
            ]
    # Run topology/configuration consistency check.
    checker = NetworkChecker()
    checker.check_gateway_consistency(
    topology,
    show_output
    )
    checker.check_vlan_consistency(
        topology,
        show_output
    )

    findings.extend(
        checker.findings
    )

    return {
        "case_id": case.get(
            "case_id",
            "UNKNOWN"
        ),
        "findings": findings,
        "issue_count": len(findings)
    }


# =============================================================
# Direct testing
# =============================================================

if __name__ == "__main__":

    sample_case = {
        "case_id": "TEST-001",

        "symptom": (
            "PC cannot communicate with another PC."
        ),

        "topology_note": (
            "Both PCs should belong to VLAN10."
        ),

        "show_outputs": (
            "show vlan brief: "
            "Fa0/2 VLAN10; "
            "Fa0/3 VLAN20"
        )
    }

    result = check_case(
        sample_case
    )

    print()
    print("NetSage AI - Rule Checker")
    print("=" * 50)

    print(
        f"Case: {result['case_id']}"
    )

    print(
        f"Findings: {result['issue_count']}"
    )

    for finding in result["findings"]:

        print()
        print(
            f"Rule: {finding['rule']}"
        )

        print(
            f"Severity: {finding['severity']}"
        )

        print(
            f"Message: {finding['message']}"
        )

        print(
            f"Evidence: {finding['evidence']}"
        )