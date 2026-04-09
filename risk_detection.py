import requests
import re
import os
from dotenv import load_dotenv


# ===============================
# LOAD TOKEN FROM .env
# ===============================
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

if not GITHUB_TOKEN:
    print("Warning: GITHUB_TOKEN not found. You may hit rate limits.")

print("Test PR Risk Detection System Initialized")
# ===============================
# FETCH PR DIFF
# ===============================
def fetch_pr_diff(owner, repo, pr_number, token=None):

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"

    headers = {
        "Accept": "application/vnd.github.v3.diff"
    }

    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.get(url, headers=headers)

    if response.status_code == 403:
        raise Exception("Rate limit exceeded or invalid token.")

    elif response.status_code == 9001:
        raise Exception("Pull Request not found.")

    elif response.status_code != 200:
        raise Exception(f"fetching PR: {response.status_code}")

    return response.text


# ===============================
# PARSE DIFF
# ===============================
def analyze_diff(diff_text):

    files = diff_text.split("diff --git")
    files = [f for f in files if f.strip()]

    total_added = 0
    total_deleted = 0
    file_changes = {}
    file_details = {}

    for file_block in files:

        filename_match = re.search(r"a/(.*?) b/", file_block)
        if not filename_match:
            continue

        filename = filename_match.group(1)

        added = 0
        deleted = 0

        for line in file_block.splitlines():

            if line.startswith("+") and not line.startswith("+++"):
                added += 1

            elif line.startswith("-") and not line.startswith("---"):
                deleted += 1

        file_changes[filename] = added + deleted
        file_details[filename] = {"added": added, "deleted": deleted}

        total_added += added
        total_deleted += deleted

    return file_changes, file_details, total_added, total_deleted


# ===============================
# RISK DETECTION
# ===============================
def detect_risk(file_changes, file_details, total_added, total_deleted):

    total_files = len(file_changes)
    total_changes = total_added + total_deleted
    largest_file_change = max(file_changes.values()) if file_changes else 0

    risk_flags = []
    score = 0

    # Edge case
    if total_files == 0:
        return {
            "pr_size": "NONE",
            "total_files": 0,
            "total_changes": 0,
            "largest_file_change": 0,
            "risk_score": 0,
            "severity": "LOW",
            "risk_flags": ["Empty PR"]
        }

    # ===============================
    # SIZE-BASED LOGIC
    # ===============================
    if total_changes <= 200:
        pr_size = "SMALL"

        if total_files <= 10:
            if total_files > 5 or largest_file_change > 50:
                risk_flags.append("Small PR (0-10 files): threshold exceeded")
                score += 20

        elif total_files <= 20:
            if total_files > 10 or largest_file_change > 40:
                risk_flags.append("Small PR (10-20 files): threshold exceeded")
                score += 20

        else:
            if total_files > 15 or largest_file_change > 30:
                risk_flags.append("Small PR (20+ files): threshold exceeded")
                score += 20

    elif total_changes <= 500:
        pr_size = "MEDIUM"

        if total_files <= 10:
            if total_files > 4 or largest_file_change > 100:
                risk_flags.append("Medium PR (0-10 files): threshold exceeded")
                score += 25

        elif total_files <= 20:
            if total_files > 8 or largest_file_change > 70:
                risk_flags.append("Medium PR (10-20 files): threshold exceeded")
                score += 25

        else:
            if total_files > 12 or largest_file_change > 50:
                risk_flags.append("Medium PR (20+ files): threshold exceeded")
                score += 25

        if total_files > 25:
            risk_flags.append("Too many files in medium PR")
            score += 20

    else:
        pr_size = "LARGE"

        if total_files <= 10:
            if total_files > 3 or largest_file_change > 150:
                risk_flags.append("Large PR (0-10 files): threshold exceeded")
                score += 30

        elif total_files <= 20:
            if total_files > 6 or largest_file_change > 120:
                risk_flags.append("Large PR (10-20 files): threshold exceeded")
                score += 30

        else:
            risk_flags.append("Large PR with >20 files is always risky")
            score += 40

        if largest_file_change > 200:
            risk_flags.append("Very large single file change")
            score += 20

        if total_files > 30:
            risk_flags.append("Too many files → critical")
            score += 25

    # ===============================
    # ADVANCED SIGNALS
    # ===============================
    if any(file.endswith(ext) for file in file_changes for ext in [".env", ".sql", ".yml", ".yaml"]):
        risk_flags.append("Sensitive file modified")
        score += 25

    if any(".github/workflows" in file for file in file_changes):
        risk_flags.append("CI/CD pipeline modified")
        score += 30

    if any(dep in file for file in file_changes for dep in ["requirements.txt", "package.json"]):
        risk_flags.append("Dependency change detected")
        score += 20

    for file, changes in file_details.items():
        if "test" in file.lower() and changes["deleted"] > changes["added"]:
            risk_flags.append("Test code removed")
            score += 30
            break

    # ===============================
    # FINAL SEVERITY
    # ===============================
    if score >= 100:
        severity = "CRITICAL"
    elif score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    risk_flags = list(set(risk_flags))

    return {
        "pr_size": pr_size,
        "total_files": total_files,
        "total_changes": total_changes,
        "largest_file_change": largest_file_change,
        "risk_score": score,
        "severity": severity,
        "risk_flags": risk_flags
    }


# ===============================
# MAIN
# ===============================
if __name__ == "__main__":

    OWNER = "sickn33"
    REPO = "antigravity-awesome-skills"
    PR_NUMBER = 1

    print("Fetching PR Diff...")
    diff = fetch_pr_diff(OWNER, REPO, PR_NUMBER, GITHUB_TOKEN)

    print("Analyzing PR...")
    file_changes, file_details, added, deleted = analyze_diff(diff)

    report = detect_risk(file_changes, file_details, added, deleted)

    print("\n===== PR RISK REPORT =====")
    print("PR Size:", report["pr_size"])
    print("Files Changed:", report["total_files"])
    print("Total Changes:", report["total_changes"])
    print("Largest File Change:", report["largest_file_change"])
    print("Risk Score:", report["risk_score"])
    print("Severity:", report["severity"])

    print("\nRisk Flags:")
    for flag in report["risk_flags"]:
        print("-", flag)