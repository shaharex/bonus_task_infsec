import os
import json
import sys
import difflib
import shutil
from pathlib import Path

from git import Repo, GitCommandError
import pandas as pd
from tqdm import tqdm


# ---------------------------------------------------------------------
# Change this if you want output in another folder
# ---------------------------------------------------------------------
OUTPUT_ROOT = "outputs"


def safe_get_commit_urls(refs):
    """extract only commit URLs from references list"""
    if not refs:
        return []
    return [r for r in refs if "/commit/" in r]


def clone_or_fetch(repo_url: str, dest: str) -> Repo:
    """Clone repo if missing, otherwise fetch latest."""
    if os.path.exists(dest) and (Path(dest) / ".git").exists():
        repo = Repo(dest)
        try:
            repo.remote().fetch()
        except Exception:
            pass
        return repo
    else:
        return Repo.clone_from(repo_url, dest)


def checkout(repo: Repo, ref: str):
    """Checkout a version or commit safely."""
    if not ref:
        return False
    try:
        repo.git.checkout(ref)
        return True
    except GitCommandError:
        try:
            repo.remote().fetch()
            repo.git.checkout(ref)
            return True
        except Exception:
            return False


def load_file_safe(path: Path):
    """Load file contents as text."""
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def generate_unified_diff(old_text, new_text, file_path):
    """Generate unified diff using Python difflib."""
    if old_text is None or new_text is None:
        return ""
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"{file_path} (old)",
        tofile=f"{file_path} (new)",
        lineterm=""
    )
    return "\n".join(diff)


def process_json(json_path, output_root):
    # Load JSON
    with open(json_path, "r", encoding="utf-8") as f:
        advisories = json.load(f)

    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    results = []

    for row in tqdm(advisories, desc="Processing advisories"):

        ghsa = row.get("ghsa_id")
        repo_url = row.get("source_code_location")
        advisory_text = row.get("description", "")

        if not repo_url:
            print(f"[SKIP] No repo_url for {ghsa}")
            continue

        # extract commit URLs
        refs = row.get("references", [])
        commit_urls = safe_get_commit_urls(refs)

        # extract vulnerabilities info
        vulns = row.get("vulnerabilities", [])
        vulnerable_ranges = [v.get("vulnerable_version_range") for v in vulns]
        patched_versions = [v.get("first_patched_version") for v in vulns]

        vuln_old = vulnerable_ranges[0] if vulnerable_ranges else None
        patched_new = patched_versions[0] if patched_versions else None

        # prepare workspace
        repo_name = repo_url.rstrip("/").split("/")[-1]
        repo_dir = output_root / f"{ghsa}_{repo_name}"

        try:
            repo = clone_or_fetch(repo_url, str(repo_dir))
        except Exception as e:
            print(f"[ERROR] Failed to clone {repo_url}: {e}")
            continue

        # -------------------------------------------------------------
        # Checkout versions
        # If commit URLs exist, prefer using the commit SHA.
        # Otherwise use version tags.
        # -------------------------------------------------------------
        # Extract commit SHA
        commit_old = None
        commit_new = None

        if commit_urls:
            if len(commit_urls) >= 1:
                commit_new = commit_urls[0].split("/")[-1]  # last part of URL
            if len(commit_urls) >= 2:
                commit_old = commit_urls[1].split("/")[-1]

        # Fallback: use vulnerable/patched versions
        if not commit_old:
            commit_old = vuln_old
        if not commit_new:
            commit_new = patched_new

        # Checkout old version
        if not checkout(repo, commit_old):
            print(f"[WARN] Could not checkout old version: {commit_old}")

        # Collect old files snapshot
        old_snapshot = {}
        for root, dirs, files in os.walk(repo_dir):
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".html", ".php")):
                    path = Path(root) / file
                    rel = str(path.relative_to(repo_dir))
                    old_snapshot[rel] = load_file_safe(path)

        # Checkout new version
        if not checkout(repo, commit_new):
            print(f"[WARN] Could not checkout patched version: {commit_new}")

        # Collect new files snapshot
        new_snapshot = {}
        for root, dirs, files in os.walk(repo_dir):
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".html", ".php")):
                    path = Path(root) / file
                    rel = str(path.relative_to(repo_dir))
                    new_snapshot[rel] = load_file_safe(path)

        # -------------------------------------------------------------
        # DIFF GENERATION
        # -------------------------------------------------------------
        diffs_dir = output_root / "diffs" / ghsa
        diffs_dir.mkdir(parents=True, exist_ok=True)

        diff_paths = []

        for file_path in old_snapshot:
            old_text = old_snapshot.get(file_path)
            new_text = new_snapshot.get(file_path)

            diff_text = generate_unified_diff(old_text, new_text, file_path)

            if diff_text.strip():
                out_path = diffs_dir / f"{file_path.replace('/', '__')}.diff"
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(diff_text, encoding="utf-8")
                diff_paths.append(str(out_path))

        # -------------------------------------------------------------
        # LLM PROMPTS
        # -------------------------------------------------------------
        prompts_dir = output_root / "prompts" / ghsa
        prompts_dir.mkdir(parents=True, exist_ok=True)

        localization_prompt = f"""
CWE-79 XSS Patch Localization Task
Advisory: {ghsa}

Identify which changes in the diffs correspond to fixing an XSS vulnerability.
Return JSON list of suspicious hunks with line numbers and reasoning.
"""

        fix_check_prompt = f"""
Patch Verification Task
Advisory: {ghsa}

Vulnerable version: {vuln_old}
Patched version: {patched_new}

Using the diffs provided, decide if the patch successfully fixes the vulnerability.
Return JSON with fields:
- fixes_vulnerability: yes/no/maybe
- confidence: 0-100
- rationale
"""

        (prompts_dir / "localization_prompt.txt").write_text(localization_prompt, encoding="utf-8")
        (prompts_dir / "fix_check_prompt.txt").write_text(fix_check_prompt, encoding="utf-8")

        results.append({
            "ghsa_id": ghsa,
            "repo_url": repo_url,
            "commit_old": commit_old,
            "commit_new": commit_new,
            "vulnerable_range": vuln_old,
            "patched_version": patched_new,
            "diff_files": diff_paths,
            "prompts_dir": str(prompts_dir)
        })

    # Save final dataset
    df = pd.DataFrame(results)
    df.to_csv(output_root / "patched_dataset.csv", index=False)
    print("DONE → saved to:", output_root / "patched_dataset.csv")


# ---------------------------------------------------------------------
# ENTRYPOINT
# ---------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py advisories.json output_folder/")
        sys.exit(1)

    json_file = sys.argv[1]
    out = sys.argv[2]

    process_json(json_file, out)
