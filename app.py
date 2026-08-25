import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="NetSage AI",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(BASE_DIR, "data")
SRC_DIR = os.path.join(BASE_DIR, "src")

CASES_FILE = os.path.join(DATA_DIR, "cases.csv")
RESULTS_FILE = os.path.join(DATA_DIR, "evaluation_results.csv")
REVIEW_FILE = os.path.join(DATA_DIR, "human_review_log.csv")

# ============================================================
# IMPORT NETSAGE MODULES
# ============================================================

import sys

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

try:
    from checker import check_case
    CHECKER_AVAILABLE = True
except Exception:
    CHECKER_AVAILABLE = False

try:
    from ai_client import ask_ai, build_strict_prompt, validate_response
    AI_AVAILABLE = True
except Exception:
    AI_AVAILABLE = False


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def load_cases():

    if not os.path.exists(CASES_FILE):
        return pd.DataFrame()

    return pd.read_csv(CASES_FILE)


def load_results():

    if not os.path.exists(RESULTS_FILE):
        return pd.DataFrame()

    return pd.read_csv(RESULTS_FILE)


def initialize_review_file():

    os.makedirs(DATA_DIR, exist_ok=True)

    if not os.path.exists(REVIEW_FILE):

        df = pd.DataFrame(
            columns=[
                "timestamp",
                "case_id",
                "decision",
                "edited_command",
                "reviewer_note"
            ]
        )

        df.to_csv(REVIEW_FILE, index=False)


def load_reviews():

    initialize_review_file()

    try:
        return pd.read_csv(REVIEW_FILE)
    except Exception:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "case_id",
                "decision",
                "edited_command",
                "reviewer_note"
            ]
        )


def save_review(
    case_id,
    decision,
    edited_command,
    reviewer_note
):

    initialize_review_file()

    new_row = pd.DataFrame([
        {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "case_id": case_id,
            "decision": decision,
            "edited_command": edited_command,
            "reviewer_note": reviewer_note
        }
    ])

    new_row.to_csv(
        REVIEW_FILE,
        mode="a",
        header=False,
        index=False
    )


def safe_value(row, column, default=""):

    if column not in row:
        return default

    value = row[column]

    if pd.isna(value):
        return default

    return value


# ============================================================
# LOAD DATA
# ============================================================

cases = load_cases()
results = load_results()

initialize_review_file()

reviews = load_reviews()


# ============================================================
# GLOBAL CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 36px;
        font-weight: 700;
        margin-bottom: 0px;
    }

    .subtitle {
        font-size: 16px;
        color: #777;
        margin-bottom: 25px;
    }

    .section-title {
        font-size: 25px;
        font-weight: 650;
        margin-top: 15px;
        margin-bottom: 15px;
    }

    .metric-card {
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #ddd;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🌐 NetSage AI")

st.sidebar.caption(
    "AI-powered network troubleshooting system"
)

dashboard = st.sidebar.radio(
    "Select Dashboard",
    [
        "📊 Executive Overview",
        "🔎 Diagnostic Explorer",
        "🛡️ Human Review & Audit"
    ]
)

st.sidebar.divider()

st.sidebar.markdown(
    "**System Status**"
)

if CHECKER_AVAILABLE:
    st.sidebar.success("✓ Rule Checker Available")
else:
    st.sidebar.error("✗ Rule Checker Unavailable")

if AI_AVAILABLE:
    st.sidebar.success("✓ Local LLM Available")
else:
    st.sidebar.warning("⚠ Local LLM Unavailable")

st.sidebar.divider()

st.sidebar.caption(
    "NetSage AI • Local Network Diagnostics"
)


# ============================================================
# DASHBOARD 1
# EXECUTIVE OVERVIEW
# ============================================================

if dashboard == "📊 Executive Overview":

    st.markdown(
        '<div class="main-title">NetSage AI — Executive Overview</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        '30-case network troubleshooting evaluation dashboard'
        '</div>',
        unsafe_allow_html=True
    )

    if cases.empty:

        st.error(
            "cases.csv was not found in the data folder."
        )

        st.stop()

    # --------------------------------------------------------
    # FILTERS
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Filters</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        concepts = sorted(
            cases["concept_tag"]
            .dropna()
            .astype(str)
            .unique()
        )

        selected_concepts = st.multiselect(
            "Concept",
            concepts
        )

    with col2:

        severities = sorted(
            cases["severity"]
            .dropna()
            .astype(str)
            .unique()
        )

        selected_severities = st.multiselect(
            "Severity",
            severities
        )

    with col3:

        layers = sorted(
            cases["osi_layer"]
            .dropna()
            .astype(str)
            .unique()
        )

        selected_layers = st.multiselect(
            "OSI Layer",
            layers
        )

    with col4:

        status_options = [
            "CORRECT",
            "INCORRECT",
            "INVALID_AI_RESPONSE"
        ]

        selected_status = st.multiselect(
            "Evaluation Status",
            status_options
        )

    filtered_cases = cases.copy()

    if selected_concepts:

        filtered_cases = filtered_cases[
            filtered_cases["concept_tag"]
            .astype(str)
            .isin(selected_concepts)
        ]

    if selected_severities:

        filtered_cases = filtered_cases[
            filtered_cases["severity"]
            .astype(str)
            .isin(selected_severities)
        ]

    if selected_layers:

        filtered_cases = filtered_cases[
            filtered_cases["osi_layer"]
            .astype(str)
            .isin(selected_layers)
        ]

    # Merge evaluation status if results available

    if not results.empty and "case_id" in results.columns:

        status_map = results[
            ["case_id", "status"]
        ].drop_duplicates(
            "case_id"
        )

        filtered_cases = filtered_cases.merge(
            status_map,
            on="case_id",
            how="left"
        )

        if selected_status:

            filtered_cases = filtered_cases[
                filtered_cases["status"]
                .isin(selected_status)
            ]

    # --------------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------------

    total = len(filtered_cases)

    if "status" in filtered_cases.columns:

        correct = (
            filtered_cases["status"]
            .eq("CORRECT")
            .sum()
        )

        incorrect = (
            filtered_cases["status"]
            .eq("INCORRECT")
            .sum()
        )

        invalid = (
            filtered_cases["status"]
            .eq("INVALID_AI_RESPONSE")
            .sum()
        )

    else:

        correct = 0
        incorrect = 0
        invalid = 0

    accuracy = (
        correct / total * 100
        if total > 0
        else 0
    )

    st.markdown(
        '<div class="section-title">Evaluation Summary</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric(
        "Total Cases",
        total
    )

    c2.metric(
        "Correct",
        correct
    )

    c3.metric(
        "Incorrect",
        incorrect
    )

    c4.metric(
        "Invalid",
        invalid
    )

    c5.metric(
        "Accuracy",
        f"{accuracy:.2f}%"
    )

    # --------------------------------------------------------
    # CHARTS
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Evaluation Analytics</div>',
        unsafe_allow_html=True
    )

    left, right = st.columns(2)

    with left:

        if "status" in filtered_cases.columns:

            status_counts = (
                filtered_cases["status"]
                .value_counts()
                .rename_axis("Status")
                .reset_index(name="Cases")
            )

            st.subheader(
                "Diagnosis Status"
            )

            st.bar_chart(
                status_counts.set_index("Status")
            )

    with right:

        if "concept_tag" in filtered_cases.columns:

            concept_counts = (
                filtered_cases["concept_tag"]
                .value_counts()
                .rename_axis("Concept")
                .reset_index(name="Cases")
            )

            st.subheader(
                "Cases by Networking Concept"
            )

            st.bar_chart(
                concept_counts.set_index("Concept")
            )

    left, right = st.columns(2)

    with left:

        severity_counts = (
            filtered_cases["severity"]
            .value_counts()
            .rename_axis("Severity")
            .reset_index(name="Cases")
        )

        st.subheader(
            "Cases by Severity"
        )

        st.bar_chart(
            severity_counts.set_index("Severity")
        )

    with right:

        layer_counts = (
            filtered_cases["osi_layer"]
            .value_counts()
            .rename_axis("OSI Layer")
            .reset_index(name="Cases")
        )

        st.subheader(
            "Cases by OSI Layer"
        )

        st.bar_chart(
            layer_counts.set_index("OSI Layer")
        )

    # --------------------------------------------------------
    # PERFORMANCE TABLE
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Case Performance</div>',
        unsafe_allow_html=True
    )

    display_columns = [
        "case_id",
        "concept_tag",
        "severity",
        "expected_fault",
        "osi_layer"
    ]

    if "status" in filtered_cases.columns:
        display_columns.append("status")

    display_columns = [
        col
        for col in display_columns
        if col in filtered_cases.columns
    ]

    st.dataframe(
        filtered_cases[display_columns],
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# DASHBOARD 2
# DIAGNOSTIC EXPLORER
# ============================================================

elif dashboard == "🔎 Diagnostic Explorer":

    st.markdown(
        '<div class="main-title">NetSage AI — Diagnostic Explorer</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'Explore individual network troubleshooting cases and AI diagnoses'
        '</div>',
        unsafe_allow_html=True
    )

    if cases.empty:
        st.error("cases.csv not found.")
        st.stop()

    # --------------------------------------------------------
    # FILTERS
    # --------------------------------------------------------

    st.sidebar.markdown("### Diagnostic Filters")

    concept_filter = st.sidebar.multiselect(
        "Concept",
        sorted(
            cases["concept_tag"]
            .dropna()
            .astype(str)
            .unique()
        )
    )

    severity_filter = st.sidebar.multiselect(
        "Severity",
        sorted(
            cases["severity"]
            .dropna()
            .astype(str)
            .unique()
        )
    )

    explorer_cases = cases.copy()

    if concept_filter:

        explorer_cases = explorer_cases[
            explorer_cases["concept_tag"]
            .astype(str)
            .isin(concept_filter)
        ]

    if severity_filter:

        explorer_cases = explorer_cases[
            explorer_cases["severity"]
            .astype(str)
            .isin(severity_filter)
        ]

    case_ids = explorer_cases["case_id"].tolist()

    if not case_ids:

        st.warning(
            "No cases match the selected filters."
        )

        st.stop()

    selected_case_id = st.selectbox(
        "Select Case",
        case_ids
    )

    case_row = explorer_cases[
        explorer_cases["case_id"]
        == selected_case_id
    ].iloc[0]

    # --------------------------------------------------------
    # CASE INFORMATION
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Case Information</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Case",
        selected_case_id
    )

    c2.metric(
        "Concept",
        safe_value(
            case_row,
            "concept_tag"
        )
    )

    c3.metric(
        "Severity",
        safe_value(
            case_row,
            "severity"
        )
    )

    c4.metric(
        "OSI Layer",
        safe_value(
            case_row,
            "osi_layer"
        )
    )

    st.subheader("Symptom")

    st.info(
        safe_value(
            case_row,
            "symptom"
        )
    )

    st.subheader("Topology")

    st.write(
        safe_value(
            case_row,
            "topology_note"
        )
    )

    st.subheader("Expected Fault")

    st.success(
        safe_value(
            case_row,
            "expected_fault"
        )
    )

    # --------------------------------------------------------
    # SHOW OUTPUT
    # --------------------------------------------------------

    st.subheader(
        "Cisco Show Output"
    )

    st.code(
        safe_value(
            case_row,
            "show_outputs"
        ),
        language="text"
    )

    # --------------------------------------------------------
    # CHECKER
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Deterministic Checker</div>',
        unsafe_allow_html=True
    )

    if CHECKER_AVAILABLE:

        try:

            case_dict = case_row.to_dict()

            checker_result = check_case(
                case_dict
            )

            findings = checker_result.get(
                "findings",
                []
            )

            if findings:

                for finding in findings:

                    with st.expander(
                        finding.get(
                            "rule",
                            "Finding"
                        ),
                        expanded=True
                    ):

                        st.write(
                            "**Severity:**",
                            finding.get(
                                "severity",
                                ""
                            )
                        )

                        st.write(
                            "**Message:**",
                            finding.get(
                                "message",
                                ""
                            )
                        )

                        st.code(
                            finding.get(
                                "evidence",
                                ""
                            ),
                            language="text"
                        )

            else:

                st.success(
                    "No deterministic checker findings."
                )

        except Exception as error:

            st.error(
                f"Checker error: {error}"
            )

    else:

        st.warning(
            "Checker module is unavailable."
        )

    # --------------------------------------------------------
    # AI DIAGNOSIS
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Local LLM Diagnosis</div>',
        unsafe_allow_html=True
    )

    if not AI_AVAILABLE:

        st.warning(
            "Local LLM is unavailable."
        )

    else:

        if st.button(
            "🤖 Run Llama Diagnosis",
            type="primary"
        ):

            try:

                case_dict = case_row.to_dict()

                checker_result = check_case(
                    case_dict
                )

                findings = checker_result.get(
                    "findings",
                    []
                )

                prompt = build_strict_prompt(
                    case_dict,
                    findings
                )

                with st.spinner(
                    "Sending evidence to local Llama..."
                ):

                    raw_response = ask_ai(
                        prompt
                    )

                validation = validate_response(
                    raw_response
                )

                if validation["valid"]:

                    diagnosis = validation[
                        "diagnosis"
                    ]

                    st.session_state[
                        "last_diagnosis"
                    ] = diagnosis

                    st.session_state[
                        "last_case_id"
                    ] = selected_case_id

                else:

                    st.error(
                        "Invalid AI response."
                    )

                    st.code(
                        raw_response,
                        language="json"
                    )

            except Exception as error:

                st.error(
                    f"AI error: {error}"
                )

        # ----------------------------------------------------
        # DISPLAY LAST DIAGNOSIS
        # ----------------------------------------------------

        if (
            "last_diagnosis"
            in st.session_state
            and st.session_state.get(
                "last_case_id"
            ) == selected_case_id
        ):

            diagnosis = st.session_state[
                "last_diagnosis"
            ]

            st.subheader(
                "AI Diagnosis"
            )

            c1, c2, c3 = st.columns(3)

            c1.metric(
                "Confidence",
                diagnosis.get(
                    "confidence",
                    ""
                )
            )

            c2.metric(
                "OSI Layer",
                diagnosis.get(
                    "osi_layer",
                    ""
                )
            )

            c3.metric(
                "Root Cause",
                diagnosis.get(
                    "root_cause",
                    ""
                )
            )

            st.write(
                "**Root Cause**"
            )

            st.success(
                diagnosis.get(
                    "root_cause",
                    ""
                )
            )

            st.write(
                "**Evidence**"
            )

            evidence = diagnosis.get(
                "evidence",
                []
            )

            for item in evidence:

                st.info(
                    str(item)
                )

            st.write(
                "**Next Command**"
            )

            st.code(
                diagnosis.get(
                    "next_command",
                    ""
                ),
                language="text"
            )

            st.write(
                "**Fix Steps**"
            )

            fix_steps = diagnosis.get(
                "fix_steps",
                []
            )

            for i, step in enumerate(
                fix_steps,
                start=1
            ):

                st.write(
                    f"{i}. {step}"
                )

            st.write(
                "**Uncertainty**"
            )

            st.warning(
                diagnosis.get(
                    "uncertainty",
                    ""
                )
            )


# ============================================================
# DASHBOARD 3
# HUMAN REVIEW & AUDIT
# ============================================================

elif dashboard == "🛡️ Human Review & Audit":

    st.markdown(
        '<div class="main-title">NetSage AI — Human Review & Audit</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'Human-in-the-loop validation and diagnosis review'
        '</div>',
        unsafe_allow_html=True
    )

    # --------------------------------------------------------
    # LOAD REVIEWS
    # --------------------------------------------------------

    reviews = load_reviews()

    # --------------------------------------------------------
    # REVIEW FILTERS
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Review Filters</div>',
        unsafe_allow_html=True
    )

    f1, f2 = st.columns(2)

    with f1:

        if not reviews.empty:

            review_case_options = sorted(
                reviews["case_id"]
                .dropna()
                .astype(str)
                .unique()
            )

        else:

            review_case_options = []

        selected_review_cases = st.multiselect(
            "Case ID",
            review_case_options
        )

    with f2:

        if not reviews.empty:

            decision_options = sorted(
                reviews["decision"]
                .dropna()
                .astype(str)
                .unique()
            )

        else:

            decision_options = []

        selected_decisions = st.multiselect(
            "Decision",
            decision_options
        )

    filtered_reviews = reviews.copy()

    if selected_review_cases:

        filtered_reviews = filtered_reviews[
            filtered_reviews["case_id"]
            .astype(str)
            .isin(selected_review_cases)
        ]

    if selected_decisions:

        filtered_reviews = filtered_reviews[
            filtered_reviews["decision"]
            .astype(str)
            .isin(selected_decisions)
        ]

    # --------------------------------------------------------
    # REVIEW KPIs
    # --------------------------------------------------------

    total_reviews = len(reviews)

    accepted = (
        reviews["decision"]
        .eq("Accepted")
        .sum()
        if not reviews.empty
        else 0
    )

    edited = (
        reviews["decision"]
        .eq("Edited")
        .sum()
        if not reviews.empty
        else 0
    )

    rejected = (
        reviews["decision"]
        .eq("Rejected")
        .sum()
        if not reviews.empty
        else 0
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Total Reviews",
        total_reviews
    )

    c2.metric(
        "Accepted",
        accepted
    )

    c3.metric(
        "Edited",
        edited
    )

    c4.metric(
        "Rejected",
        rejected
    )

    # --------------------------------------------------------
    # NEW REVIEW
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Review AI Diagnosis</div>',
        unsafe_allow_html=True
    )

    if cases.empty:

        st.warning(
            "cases.csv not found."
        )

    else:

        review_case_id = st.selectbox(
            "Select case for review",
            cases["case_id"].tolist(),
            key="review_case_selector"
        )

        selected_case = cases[
            cases["case_id"]
            == review_case_id
        ].iloc[0]

        st.subheader(
            f"Case {review_case_id}"
        )

        st.write(
            "**Symptom:**",
            safe_value(
                selected_case,
                "symptom"
            )
        )

        st.write(
            "**Expected Fault:**",
            safe_value(
                selected_case,
                "expected_fault"
            )
        )

        st.write(
            "**Network Evidence:**"
        )

        st.code(
            safe_value(
                selected_case,
                "show_outputs"
            ),
            language="text"
        )

        # ----------------------------------------------------
        # AI RESULT
        # ----------------------------------------------------

        diagnosis = None

        if (
            "last_diagnosis"
            in st.session_state
            and st.session_state.get(
                "last_case_id"
            ) == review_case_id
        ):

            diagnosis = st.session_state[
                "last_diagnosis"
            ]

        if diagnosis:

            st.subheader(
                "Current AI Diagnosis"
            )

            st.success(
                diagnosis.get(
                    "root_cause",
                    ""
                )
            )

            st.write(
                "**Confidence:**",
                diagnosis.get(
                    "confidence",
                    ""
                )
            )

            st.write(
                "**Next Command:**"
            )

            default_command = diagnosis.get(
                "next_command",
                ""
            )

            edited_command = st.text_input(
                "CLI command",
                value=default_command,
                key="review_command"
            )

            st.write(
                "**Evidence:**"
            )

            for evidence in diagnosis.get(
                "evidence",
                []
            ):

                st.info(
                    str(evidence)
                )

            st.write(
                "**Fix Steps:**"
            )

            for step in diagnosis.get(
                "fix_steps",
                []
            ):

                st.write(
                    f"• {step}"
                )

        else:

            st.info(
                "Run a diagnosis from the Diagnostic "
                "Explorer first, then review it here."
            )

            edited_command = ""

        # ----------------------------------------------------
        # HUMAN DECISION
        # ----------------------------------------------------

        decision = st.radio(
            "Human Decision",
            [
                "Accepted",
                "Edited",
                "Rejected"
            ],
            horizontal=True
        )

        reviewer_note = st.text_area(
            "Reviewer Notes",
            placeholder=(
                "Explain why the diagnosis was accepted, "
                "edited, or rejected..."
            )
        )

        if st.button(
            "💾 Save Review",
            type="primary"
        ):

            save_review(
                review_case_id,
                decision,
                edited_command,
                reviewer_note
            )

            st.success(
                "Review saved successfully."
            )

            st.rerun()

    # --------------------------------------------------------
    # AUDIT TABLE
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">Audit History</div>',
        unsafe_allow_html=True
    )

    if filtered_reviews.empty:

        st.info(
            "No human reviews have been recorded yet."
        )

    else:

        st.dataframe(
            filtered_reviews,
            use_container_width=True,
            hide_index=True
        )

        # ----------------------------------------------------
        # REVIEW ANALYTICS
        # ----------------------------------------------------

        st.subheader(
            "Review Decision Distribution"
        )

        decision_counts = (
            filtered_reviews["decision"]
            .value_counts()
            .rename_axis("Decision")
            .reset_index(name="Reviews")
        )

        st.bar_chart(
            decision_counts.set_index(
                "Decision"
            )
        )


# ============================================================
# FOOTER
# ============================================================

st.sidebar.divider()

st.sidebar.caption(
    "NetSage AI | Local LLM Network Diagnostics"
)