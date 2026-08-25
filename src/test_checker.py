import pandas as pd

from checker import check_case


def main():

    # Load the troubleshooting dataset
    data = pd.read_csv("data/cases.csv")

    print("=" * 65)
    print("NETSAGE AI - RULE CHECKER TEST")
    print("=" * 65)

    print(f"\nTotal cases loaded: {len(data)}")

    total_findings = 0
    cases_with_findings = 0

    print("\nCase Results")
    print("-" * 65)

    for _, row in data.iterrows():

        case = row.to_dict()

        result = check_case(case)

        finding_count = result["issue_count"]

        total_findings += finding_count

        if finding_count > 0:
            cases_with_findings += 1

        print(
            f"{result['case_id']:10} | "
            f"Findings: {finding_count}"
        )

        for finding in result["findings"]:

            print(
                f"           └─ "
                f"[{finding['severity']}] "
                f"{finding['rule']}: "
                f"{finding['message']}"
            )

    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)

    print(f"Total cases          : {len(data)}")
    print(f"Cases with findings  : {cases_with_findings}")
    print(f"Total findings       : {total_findings}")

    print("=" * 65)


if __name__ == "__main__":
    main()