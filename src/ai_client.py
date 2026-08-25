import json
import ollama
from ollama import Client
from checker import check_case


MODEL_NAME = "llama3.2:1b"


def ask_ai(prompt):
    """
    Send a prompt to the local Llama model with a timeout.
    Prevents one slow request from freezing the evaluation.
    """

    try:
        client = Client(
            host="http://127.0.0.1:11434",
            timeout=120
        )

        response = client.chat(
            model=MODEL_NAME,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            format="json",
            options={
                "temperature": 0,
                "num_predict": 180
            }
        )

        return response["message"]["content"]

    except Exception as e:
        print(f"\nAI request failed: {e}")
        return ""

def get_concept_guidance(concept):
    """
    Provide focused diagnostic guidance to the small local LLM.
    This reduces vague answers while keeping the final diagnosis
    evidence-based.
    """

    concept = str(concept).strip().lower()

    guidance = {
        
        "vlan": """
Focus on identifying the exact switch port with the wrong VLAN.
Use the interface and VLAN numbers from the evidence.
""",

        "inter-vlan routing": """
Distinguish between:
- incorrect VLAN encapsulation ID
- administratively disabled subinterface
- other inter-VLAN configuration problems.

If 'encapsulation dot1q' appears in the evidence, identify
the VLAN ID mismatch specifically.
""",

        "trunking": """
Determine whether:
- the required VLAN is missing from the trunk allowed list, or
- the inter-switch link is operating as an access port.

Use the exact evidence supplied.
""",

        "switch port configuration": """
Determine whether the endpoint port is incorrectly configured
as a trunk instead of an access port.
Identify the interface when available.
""",

        "interface status": """
This case is specifically about interface operational state.

If the evidence contains:
"administratively down"
or
"administratively disabled"

the root cause MUST be identified as an interface shutdown.

Do NOT diagnose VLAN encapsulation unless the evidence explicitly
shows an encapsulation mismatch.

Identify the exact affected interface.
""",

        "vlan database": """
Determine whether the required VLAN exists in the VLAN database.
""",

        "dhcp": """
Determine whether the DHCP pool specifies an incorrect
default-router address. Do not confuse this with a DHCP relay
or missing-pool problem.
""",

        "dhcp relay": """
Distinguish between:
- missing ip helper-address
- incorrect ip helper-address.

Use the exact helper-address evidence.
""",

        "dhcp pool": """
Determine whether the DHCP pool for the specified VLAN is missing.
""",

        "dhcp exclusion": """
Determine whether the router gateway address was excluded
from the DHCP allocation range.
""",

        "dns": """
Determine whether the client has an incorrect DNS server address
or whether the DNS server itself is timing out. Do not confuse
these two conditions.
""",

        "static routing": """
Determine whether the required route or return route is missing.
Identify the affected destination when supplied.
""",

        "ospf": """
Identify the exact OSPF fault.

If the evidence shows OSPF is not enabled on the required
interface/network, diagnose OSPF being disabled.

If the evidence shows different hello/dead timer values,
diagnose an OSPF timer mismatch.

Do NOT return a generic "OSPF problem" when the evidence
supports one of these specific faults.
""",
        "acl": """
        
Identify the exact traffic type affected by the ACL.

Distinguish between:
- HTTPS
- SSH
- ICMP
- guest-to-server traffic

Do not return the generic diagnosis "ACL_DENY" when the evidence
identifies the specific traffic.

Determine the exact ACL behavior:
- HTTPS denied
- SSH denied
- ICMP denied
- guest-to-server traffic incorrectly permitted.

Do not give a generic ACL diagnosis.
""",

        "nat": """
Determine whether NAT inside/outside roles are incorrectly
configured or whether NAT translations are failing for another
reason.
""",

        "pat": """
Determine whether the NAT/PAT ACL includes the required VLAN
source network. Identify the VLAN when present.
""",

        "wireless dhcp": """
Determine whether the access point is connected to the wrong VLAN.
""",

        "wireless vlan": """
Determine whether the AP switch port is assigned to the wrong
access VLAN. Identify the actual and expected VLANs when supplied.
""",

        "wireless security": """
Determine whether wireless client isolation is disabled.
""",

        "wireless routing": """
Determine whether the wireless network is missing the default
route toward the ISP.
"""
    }

    return guidance.get(
        concept,
        "Identify the most specific fault directly supported by the evidence."
    )

def build_strict_prompt(case, findings):
    """
    Build an evidence-grounded diagnostic prompt.
    """
    guidance = get_concept_guidance(
    case.get("concept_tag", "")
    )
    return f"""
You are NetSage AI, a Cisco networking troubleshooting assistant.

Your job is to diagnose ONLY from the evidence supplied below.

STRICT RULES:

1. Never invent devices, PCs, IP addresses, VLANs,
   interfaces, commands, configurations, or command output.

2. Never assume information that is not explicitly present
   in the supplied evidence.

3. Treat show_outputs as the primary technical evidence.

4. The deterministic checker findings are supporting evidence.

5. If the evidence is insufficient, explicitly say:
   "Insufficient evidence."

6. Do not use expected_fault to determine your answer.
   expected_fault is hidden evaluation information.

7. Return ONLY valid JSON.
   Do not use Markdown.
   Do not put ``` around the JSON.

8. The "osi_layer" field MUST be exactly one of:
   "Layer 2"
   "Layer 3"
   "Layer 4"
   "Layer 7"
   "Unknown"

9. The "confidence" field MUST be exactly one of:
   "High"
   "Medium"
   "Low"

10. The "evidence" list must contain only facts
    explicitly present in the case or checker findings.

11. "fix_steps" must describe concrete troubleshooting
    or remediation actions supported by the evidence.

12. Do not say that a PC has a configuration problem
    when the evidence identifies a switch port problem.

13. For VLAN problems, identify the affected switch
    interface when it is present in the evidence.

14. "uncertainty" must explain what is known and what
    still requires human verification.
15. Cisco verification commands must be valid IOS commands.
    Do not append an interface name to "show vlan brief".
    If checking a specific interface configuration, use:
    "show running-config interface <interface>".
    
16. Always prefer the most specific fault supported by the
    evidence over a broad category label.

17. Do not use generic answers such as:
    "Inter-VLAN Routing"
    "DHCP problem"
    "OSPF problem"
    "Wireless configuration requires verification"
    when the evidence supports a more specific diagnosis.

18. The root_cause should describe the actual configuration
    fault, not merely the networking topic.
19. DETERMINISTIC CHECKER FINDINGS HAVE PRIORITY.
   Treat the supplied checker findings as the primary evidence.
   Do not replace a specific checker finding with a broader
   networking category.

20. If the checker reports INTERFACE_SHUTDOWN and the evidence
   contains "administratively down" or "administratively disabled",
   diagnose the interface as shut down. Do not call it an
   encapsulation problem unless the evidence explicitly shows
   an encapsulation mismatch.

21. If the checker reports TRUNK_ALLOWED_VLAN, diagnose the
   missing VLAN from the trunk allowed list.

22. If the checker reports TRUNK_MODE, diagnose the interface
   operating as an access port instead of a trunk.

23. If the checker reports DHCP_RELAY_WRONG, diagnose the
   incorrect ip helper-address.

24. If the checker reports RETURN_ROUTE, diagnose the missing
   return route.

25. If the checker reports OSPF_DISABLED, diagnose OSPF as
   disabled or not enabled on the relevant network/interface.

26. If the checker reports OSPF_TIMERS, diagnose the mismatch
   between the OSPF hello/dead timers.

27. If the checker reports ACL_SSH, diagnose the ACL blocking
   SSH traffic on TCP port 22.

28. If the checker reports ACL_ICMP, diagnose the ACL blocking
   ICMP traffic.

29. If the checker reports NAT_VLAN20, diagnose VLAN20 being
   absent from the NAT ACL.

30. If the checker reports WIRELESS_WRONG_VLAN, diagnose the
   access point being connected to the wrong VLAN.
31. Do not invent facts that are not present in the evidence.

32. The uncertainty field must only mention information that
    is genuinely missing from the supplied evidence.

33. Fix steps must directly address the diagnosed fault.
    Do not suggest checking unrelated configuration unless
    the evidence indicates that it may be relevant.

34. For INTERFACE_SHUTDOWN, the fix should focus on verifying
    the interface state and bringing the interface up if
    appropriate. Do not assume an encapsulation problem.
35. Keep the response concise.

36. fix_steps must contain EXACTLY 2 short steps.

37. Each fix step must be one sentence and no more than
    15 words.

38. Do not repeat the same fix step.

39. Do not generate explanations outside the JSON object.

40. The entire JSON response must remain short enough to
    complete within the response limit.
{{
    "root_cause": "string",
    "osi_layer": "string",
    "confidence": "High|Medium|Low",
    "evidence": ["string"],
    "next_command": "string",
    "fix_steps": [
    "short step 1",
    "short step 2"
    ],
    "uncertainty": "string"
}}

CASE INFORMATION

Case ID:
{case.get("case_id", "")}

Symptom:
{case.get("symptom", "")}

Topology:
{case.get("topology_note", "")}

Concept:
{case.get("concept_tag", "")}

Severity:
{case.get("severity", "")}

SHOW OUTPUT:
{case.get("show_outputs", "")}

DETERMINISTIC CHECKER FINDINGS:
{json.dumps(findings, indent=2)}

CONCEPT-SPECIFIC DIAGNOSTIC GUIDANCE:
{guidance}
Now produce the diagnosis.

Before answering, internally verify:

- Is every claim supported by the supplied evidence?
- Did I identify the actual affected interface?
- Is the OSI layer one of the allowed values?
- Are the fix steps specific and evidence-based?
- Did I avoid inventing any network information?

Remember:
Use ONLY the information supplied above.
Do NOT invent missing evidence.
"""

def validate_response(response):
    """
    Validate and normalize the model's JSON response.
    """

    # Remove accidental Markdown fences.
    cleaned = response.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]

    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]

    cleaned = cleaned.strip()

    try:
        result = json.loads(cleaned)
        # Normalize common Cisco verification commands.
        
        command_map = {
        "show vlan brief Fa0/3": "show vlan brief",
        "show vlan brief interface": "show vlan brief",
        "show vlan": "show vlan brief"
        }

        if result.get("next_command") in command_map:
           result["next_command"] = command_map[
         result["next_command"]
        ]

    except json.JSONDecodeError as error:

        return {
            "valid": False,
            "error": str(error),
            "raw_response": response
        }

    required_fields = [
        "root_cause",
        "osi_layer",
        "confidence",
        "evidence",
        "next_command",
        "fix_steps",
        "uncertainty"
    ]

    missing = [
        field
        for field in required_fields
        if field not in result
    ]

    if missing:

        return {
            "valid": False,
            "error": (
                "Missing required fields: "
                + ", ".join(missing)
            ),
            "raw_response": response
        }
    
    allowed_layers = [
    "Layer 2",
    "Layer 3",
    "Layer 4",
    "Layer 7",
    "Unknown"
    ]

    if result["osi_layer"] not in allowed_layers:

      return {
        "valid": False,
        "error": (
            "Invalid OSI layer: "
            + str(result["osi_layer"])
        ),
        "raw_response": response
        }
    
    if result["confidence"] not in [
        "High",
        "Medium",
        "Low"
    ]:

        return {
            "valid": False,
            "error": "Invalid confidence value.",
            "raw_response": response
        }

    return {
        "valid": True,
        "diagnosis": result
    }


def main():

    # ---------------------------------------------------------
    # Use the real NET-002 case from cases.csv
    # ---------------------------------------------------------

    import pandas as pd

    data = pd.read_csv(
        "data/cases.csv"
    )

    case = data[data["case_id"] == "NET-002"].iloc[0].to_dict()

    # ---------------------------------------------------------
    # Run deterministic checker
    # ---------------------------------------------------------

    checker_result = check_case(
        case
    )

    findings = checker_result[
        "findings"
    ]

    print("=" * 70)
    print("NETSAGE AI - LOCAL LLM DIAGNOSTIC TEST")
    print("=" * 70)

    print(
        f"\nCase: {case['case_id']}"
    )

    print(
        f"Checker findings: {len(findings)}"
    )

    # ---------------------------------------------------------
    # Build strict prompt
    # ---------------------------------------------------------

    prompt = build_strict_prompt(
        case,
        findings
    )

    # ---------------------------------------------------------
    # Ask Llama
    # ---------------------------------------------------------

    print("\nSending evidence to Llama 3.2 1B...")

    raw_response = ask_ai(
        prompt
    )

    # ---------------------------------------------------------
    # Validate response
    # ---------------------------------------------------------

    validation = validate_response(
    raw_response
    )

    if validation["valid"]:

      diagnosis = validation["diagnosis"]

    # ---------------------------------------------------------
    # Deterministic evidence guard
    # ---------------------------------------------------------

      if findings:

        strongest = findings[0]

        diagnosis["root_cause"] = strongest["message"]
        diagnosis["fault_category"] = strongest["rule"]

        if strongest["rule"] in [
            "VLAN_MISMATCH",
            "MISSING_VLAN",
            "TRUNK_VLAN_PROBLEM"
        ]:
            diagnosis["osi_layer"] = "Layer 2"

        if strongest["severity"] == "HIGH":
            diagnosis["confidence"] = "High"

        diagnosis["evidence"] = [
            strongest["evidence"]
        ]

      result = {
        "valid": True,
        "diagnosis": diagnosis
      }

    else:
        result = validation
    print("\n" + "=" * 70)
    print("AI RESPONSE")
    print("=" * 70)

    if result["valid"]:

        print(
            json.dumps(
                result["diagnosis"],
                indent=4
            )
        )

    else:

        print("INVALID AI RESPONSE")
        print(
            "Reason:",
            result["error"]
        )

        print("\nRaw response:")
        print(
            result["raw_response"]
        )


if __name__ == "__main__":
    main()