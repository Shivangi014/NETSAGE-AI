NetSage AI

NetSage AI is an AI-powered network troubleshooting and diagnostic system that combines a deterministic rule-based network checker with a local Llama 3.2 1B language model to identify and explain common network configuration problems.

The system analyzes network symptoms, topology information, and Cisco diagnostic outputs to determine the root cause, OSI layer, confidence level, supporting evidence, and recommended troubleshooting steps.

🚀 Key Features
🔍 Automated network fault detection
🤖 Local Llama 3.2 1B AI diagnosis
🛡️ Deterministic rule-based evidence checker
📊 Interactive Streamlit dashboard
🧪 30-case diagnostic evaluation
📈 Accuracy evaluation and performance tracking
🏷️ Automatic fault categorization
💡 Root-cause analysis and troubleshooting recommendations
📋 Cisco verification commands
🎯 Confidence-level assessment
📁 Evaluation results exported to CSV
🛠️ Technologies Used
Python
Llama 3.2 1B
Streamlit
Pandas
Regular Expressions (Regex)
Cisco Networking Concepts
CSV
Git & GitHub
🏗️ System Architecture
Network Case / Cisco Output
            ↓
      Rule-Based Checker
            ↓
      Verified Evidence
            ↓
       Llama 3.2 1B
            ↓
     JSON Response
            ↓
     Response Validator
            ↓
    Fault Classification
            ↓
      Streamlit Dashboard
🔎 Network Faults Covered

The system evaluates multiple networking scenarios, including:

VLAN mismatch
Interface shutdown
Default gateway mismatch
VLAN encapsulation errors
Trunk configuration problems
Missing VLANs
DHCP configuration issues
DNS configuration issues
Static routing problems
Return-route problems
OSPF configuration and timer issues
ACL problems
NAT configuration problems
Wireless VLAN issues
Wireless client isolation
Missing wireless default routes
📊 Evaluation

The system was evaluated using 30 predefined network diagnostic cases.

Final Evaluation Result
Metric	Result
Total Cases	30
Correct Diagnoses	30
Incorrect	0
Invalid Responses	0
Accuracy	100%

The evaluation results are automatically saved to:

data/evaluation_results.csv
📂 Project Structure
NetSage-AI/
│
├── data/
│   ├── cases.csv
│   └── evaluation_results.csv
│
├── src/
│   ├── ai_client.py
│   ├── checker.py
│   └── evaluate.py
│
├── app.py
├── requirements.txt
├── README.md
└── documentation/
⚙️ Installation

Clone the repository:

git clone <your-github-repository-url>
cd NetSage-AI

Create a virtual environment:

python -m venv venv

Activate it on Windows:

venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt
▶️ Running the Evaluation

Run the 30-case evaluation:

python src/evaluate.py

The program evaluates each case and displays:

Status
Predicted diagnosis
Expected diagnosis
Predicted category
Expected category

At the end, it displays the overall accuracy.

🖥️ Running the Streamlit Dashboard

Run:

streamlit run app.py

The dashboard provides interactive views for:

Network diagnostics
Evaluation results
Fault categories
Diagnostic performance
Case-level analysis
Filtering and exploration of results
📌 Example Diagnosis
{
    "root_cause": "G0/0.20 is administratively down.",
    "osi_layer": "Layer 2",
    "confidence": "High",
    "evidence": [
        "G0/0.20 192.168.20.1 administratively down"
    ],
    "next_command": "show running-config interface G0/0.20",
    "fix_steps": [
        "Verify VLAN ID on G0/0.20",
        "Bring interface up on G0/0.20"
    ]
}
🎯 Objectives
Automate network troubleshooting
Reduce manual diagnosis time
Provide evidence-based network diagnoses
Combine deterministic networking rules with LLM reasoning
Improve the reliability of AI-generated troubleshooting responses
Present diagnostic results through an easy-to-use dashboard
🔮 Future Enhancements
Add more network fault scenarios
Support IPv6, BGP, STP, VPN, and advanced firewall troubleshooting
Add real-time network monitoring
Integrate live Cisco device data
Add historical diagnostic tracking
Improve visualization and reporting
Support additional local LLM models
👩‍💻 Author

Shivangi

BTech – Computer Science & Engineering
