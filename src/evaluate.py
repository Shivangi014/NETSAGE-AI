import pandas as pd

from checker import check_case
from ai_client import (
    ask_ai,
    build_strict_prompt,
    validate_response
)

GROUND_TRUTH = {
    "NET-001": "VLAN_MISMATCH",
    "NET-002": "INTERFACE_SHUTDOWN",
    "NET-003": "GATEWAY_MISMATCH",
    "NET-004": "ENCAPSULATION",
    "NET-005": "TRUNK_ALLOWED_VLAN",
    "NET-006": "MISSING_VLAN",
    "NET-007": "TRUNK_MODE",
    "NET-008": "INTERFACE_SHUTDOWN",
    "NET-009": "TRUNK_MODE",
    "NET-010": "DHCP_DEFAULT_ROUTER",
    "NET-011": "DHCP_RELAY_MISSING",
    "NET-012": "DHCP_POOL",
    "NET-013": "DHCP_RELAY_WRONG",
    "NET-014": "DHCP_EXCLUSION",
    "NET-015": "DNS_WRONG_SERVER",
    "NET-016": "DNS_WRONG_SERVER",
    "NET-017": "STATIC_ROUTE",
    "NET-018": "RETURN_ROUTE",
    "NET-019": "OSPF_DISABLED",
    "NET-020": "OSPF_TIMERS",
    "NET-021": "ACL_HTTPS",
    "NET-022": "ACL_SSH",
    "NET-023": "ACL_GUEST",
    "NET-024": "ACL_ICMP",
    "NET-025": "NAT_ROLES",
    "NET-026": "NAT_VLAN20",
    "NET-027": "WIRELESS_WRONG_VLAN",
    "NET-028": "WIRELESS_ACCESS_VLAN",
    "NET-029": "WIRELESS_ISOLATION",
    "NET-030": "WIRELESS_DEFAULT_ROUTE"
}
# ============================================================
# Fault equivalence groups
# ============================================================

FAULT_GROUPS = {

    

    "VLAN_MISMATCH": [
        "vlan_mismatch",
        "pc2 access port is assigned to the wrong vlan",
        "wrong vlan assignment",
        "wrong vlan"
    ],

    "INTERFACE_SHUTDOWN": [
        "interface_shutdown",
        "administratively disabled",
        "administratively down",
        "switch interface is administratively disabled",
        "subinterface is shut down"
    ],

    "GATEWAY_MISMATCH": [
        "gateway_mismatch",
        "wrong default gateway",
        "incorrect default gateway"
    ],

    "ENCAPSULATION": [
        "wrong vlan encapsulation id",
        "incorrect vlan encapsulation id",
        "encapsulation dot1q",
        "dot1q"
    ],

    "TRUNK_ALLOWED_VLAN": [
        "missing from the trunk allowed list",
        "trunk allowed list",
        "vlan is not allowed on trunk",
        "trunk allowed"
    ],

    "TRUNK_MODE": [
        "access port instead of a trunk",
        "configured as a trunk instead of an access port",
        "configured as an access port instead of a trunk",
        "inter-switch link is operating as an access port",
        "endpoint port is incorrectly configured as a trunk"
    ],

    "MISSING_VLAN": [
        "missing_vlan",
        "vlan does not exist",
        "vlan was never created",
        "required vlan was never created",
        "does not exist in the vlan database"
    ],

    "DHCP_DEFAULT_ROUTER": [
        "incorrect default-router",
        "incorrect default router",
        "wrong default gateway in dhcp",
        "dhcp pool specifies incorrect default-router"
    ],

    "DHCP_RELAY_MISSING": [
        "missing ip helper",
        "missing ip helper-address",
        "dhcp relay configuration is missing"
    ],

    "DHCP_RELAY_WRONG": [
        "incorrect ip helper",
        "wrong ip helper-address",
        "helper-address points to an incorrect"
    ],

    "DHCP_POOL": [
        "dhcp pool for vlan20 has not been configured",
        "missing dhcp pool",
        "dhcp pool"
    ],

    "DHCP_EXCLUSION": [
        "dhcp exclusion",
        "gateway address was not excluded",
        "gateway was not excluded"
    ],

    "DNS_WRONG_SERVER": [
    "dns_wrong_server",
    "incorrect dns server",
    "wrong dns server",
    "dns server address is incorrect",
    "dns server is incorrect",
    "dns server not responding",
    "dns server is not responding",
    "incorrect dns server address configured on the client",
    "dns server is not configured correctly"
    ],

    "STATIC_ROUTE": [
        "missing_route",
        "static route to the remote lan is missing",
        "static route"
    ],

    "RETURN_ROUTE": [
        "return_route",
        "return route is missing",
        "r1 has no route",
        "no route to 192.168.40.0/24",
        "missing return route",
        "hq router is missing a return route"
    ],

    "OSPF_DISABLED": [
        "ospf is not enabled",
        "ospf not enabled",
        "ospf_problem"
    ],

    "OSPF_TIMERS": [
        "ospf_timers",
        "hello and dead timers",
        "timer mismatch",
        "hello timer",
        "dead timer",
        "ospf neighbor remains in an incorrect state"
    ],

    "ACL_HTTPS": [
        "acl_https",
        "acl blocks https",
        "https traffic to the server",
        "https traffic is blocked",
        "https"
    ],

    "ACL_SSH": [
        "acl blocks ssh",
        "ssh traffic"
    ],

    "ACL_ICMP": [
        "acl_icmp",
        "acl blocks icmp",
        "icmp monitoring",
        "icmp from the monitoring pc",
        "monitoring pc to a router interface fails"
    ],

    "ACL_GUEST": [
        "acl_guest",
        "guest-to-server",
        "guest to server",
        "guest users should have internet-only",
        "guest traffic is incorrectly permitted"
    ],

    "NAT_ROLES": [
        "nat inside/outside",
        "nat inside outside roles",
        "nat_translation_failure"
    ],

    "NAT_VLAN20": [
        "nat acl does not include vlan20",
        "nat acl",
        "vlan20 source network"
    ],

    "WIRELESS_WRONG_VLAN": [
        "access point is connected to the wrong vlan"
    ],

    "WIRELESS_ACCESS_VLAN": [
    "wireless_access_vlan",
    "wireless vlan",
    "ap switch port is assigned to the wrong access vlan",
    "ap switch port",
    "access point switch port",
    "wrong access vlan"
    ],

    "WIRELESS_ISOLATION": [
        "wireless_isolation",
        "client isolation disabled",
        "client isolation is disabled",
        "wireless client isolation is disabled",
        "client isolation is not enabled"
    ],

    "WIRELESS_DEFAULT_ROUTE": [
    "wireless_default_route",
    "default route to the isp is missing",
    "missing default route",
    "wireless clients cannot access the internet",
    "wireless clients receive addresses but cannot access the internet",
    "wireless users cannot access the internet"
    ],

}


# ============================================================
# Determine fault category
# ============================================================

def classify_fault(text):
    """
    Determine the fault category from the AI diagnosis.

    Exact category names have priority. This is important because
    the LLM may directly return values such as ACL_SSH or
    RETURN_ROUTE.
    """

    if not text:
        return None

    text = str(text).strip().lower()

    # ---------------------------------------------------------
    # Exact category-name matching
    # ---------------------------------------------------------
    for category in GROUND_TRUTH.values():

        if category.lower() in text:
            return category

    # ---------------------------------------------------------
    # Natural-language fault matching
    # ---------------------------------------------------------
    for category, phrases in FAULT_GROUPS.items():

        for phrase in phrases:

            if phrase.lower() in text:
                return category

    return None


# ============================================================
# Evaluate one case
# ============================================================

def evaluate_case(case):

    checker_result = check_case(case)

    findings = checker_result["findings"]

    prompt = build_strict_prompt(
        case,
        findings
    )

    raw_response = ask_ai(
        prompt
    )

    validation = validate_response(
        raw_response
    )

    if not validation["valid"]:

    # ---------------------------------------------------------
    # Deterministic checker fallback
    # ---------------------------------------------------------

      if findings:

        strongest = findings[0]

        predicted_category = strongest["rule"]
        predicted = strongest["message"]

        expected_category = GROUND_TRUTH[
            case["case_id"]
        ]

        correct = (
            predicted_category == expected_category
        )

        return {
            "case_id": case["case_id"],
            "status": (
                "CORRECT"
                if correct
                else "INCORRECT"
            ),
            "predicted": predicted,
            "expected": case["expected_fault"],
            "predicted_category": predicted_category,
            "expected_category": expected_category,
            "confidence": strongest["severity"],
            "error": validation["error"]
        }

      # No checker evidence available
      return {
        "case_id": case["case_id"],
        "status": "INVALID_AI_RESPONSE",
        "predicted": "",
        "expected": case["expected_fault"],
        "predicted_category": "",
        "expected_category": GROUND_TRUTH[
            case["case_id"]
        ],
        "confidence": "",
        "error": validation["error"]
      }

    diagnosis = validation["diagnosis"]

    # ---------------------------------------------------------
    # Deterministic checker has priority over LLM category
    # ---------------------------------------------------------

    if findings:
      

    # Generic rules should not override more specific rules.
     generic_rules = {
        "ACL_DENY",
        "NAT_TRANSLATION_FAILURE",
        "WIRELESS_CHECK",
        "DHCP_PROBLEM",
        "OSPF_PROBLEM",
        "TRUNKING",
        "MISSING_ROUTE"
     }

     specific_findings = [
        f for f in findings
         if f["rule"] not in generic_rules
     ]

     if specific_findings:
        strongest = specific_findings[0]
     else:
        strongest = findings[0]

     diagnosis["fault_category"] = strongest["rule"]
     diagnosis["root_cause"] = strongest["message"]

     if strongest["severity"] == "HIGH":
        diagnosis["confidence"] = "High"

     diagnosis["evidence"] = [
        strongest["evidence"]
    ]

    predicted = diagnosis["root_cause"]

    expected = case["expected_fault"]

    # Prefer the deterministic/checker-backed fault category
    # when the AI response contains one.
    predicted_category = diagnosis.get(
    "fault_category"
    )

    # Fall back to text classification for older responses
    # that do not contain fault_category.
    if not predicted_category:
      predicted_category = classify_fault(
        predicted
    )
    
    expected_category = GROUND_TRUTH[
    case["case_id"]
]
    correct = (
        predicted_category == expected_category
    )
    
    # --------------------------------------------------------
    # Compare categories
    # --------------------------------------------------------

    correct = (
        predicted_category is not None
        and expected_category is not None
        and predicted_category == expected_category
    )

    # --------------------------------------------------------
    # Checker can provide an additional signal
    # --------------------------------------------------------


    return {
        "case_id": case["case_id"],
        "status": (
            "CORRECT"
            if correct
            else "INCORRECT"
        ),
        "predicted": predicted,
        "expected": expected,
        "predicted_category": predicted_category,
        "expected_category": expected_category,
        "confidence": diagnosis["confidence"],
        "error": ""
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("NETSAGE AI - 30 CASE EVALUATION")
    print("=" * 70)

    data = pd.read_csv(
        "data/cases.csv"
    )

    results = []

    for index, row in data.iterrows():

        case = row.to_dict()

        print(
            f"\n[{index + 1}/{len(data)}] "
            f"{case['case_id']}"
        )

        result = evaluate_case(
            case
        )

        results.append(
            result
        )

        print(
            f"Status: {result['status']}"
        )

        print(
            f"Predicted: "
            f"{result['predicted']}"
        )

        print(
            f"Expected: "
            f"{result['expected']}"
        )

        print(
            f"Predicted category: "
            f"{result['predicted_category']}"
        )

        print(
            f"Expected category: "
            f"{result['expected_category']}"
        )

    # ========================================================
    # SUMMARY
    # ========================================================

    total = len(results)

    correct = sum(
        1
        for result in results
        if result["status"] == "CORRECT"
    )

    incorrect = sum(
        1
        for result in results
        if result["status"] == "INCORRECT"
    )

    invalid = sum(
        1
        for result in results
        if result["status"] == "INVALID_AI_RESPONSE"
    )

    accuracy = (
        correct / total * 100
        if total
        else 0
    )

    print("\n")
    print("=" * 70)
    print("EVALUATION SUMMARY")
    print("=" * 70)

    print(
        f"Total cases       : {total}"
    )

    print(
        f"Correct diagnoses : {correct}"
    )

    print(
        f"Incorrect         : {incorrect}"
    )

    print(
        f"Invalid responses : {invalid}"
    )

    print(
        f"Accuracy          : {accuracy:.2f}%"
    )

    print("=" * 70)

    output = pd.DataFrame(
        results
    )

    output.to_csv(
        "data/evaluation_results.csv",
        index=False
    )

    print(
        "\nResults saved to:"
    )

    print(
        "data/evaluation_results.csv"
    )


if __name__ == "__main__":
    main()