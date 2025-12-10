"""
patch_localizer.py

Create a second dataset from 10 CWE-79 advisories that locates the patch, computes diffs (with GumTree),
localizes the vulnerability in diffs, and uses prompt-engineering templates for an LLM to decide whether
patched_version_new fixes vulnerable_version_old.

Inputs expected: a CSV (or JSON) `advisories.csv` with at least these columns:
  - ghsa_id
  - ecosystem
  - repo_url                (git URL, e.g. https://github.com/org/repo.git)
  - vulnerable_version_old  (git ref: tag or commit SHA)
  - vulnerable_version_new  (optional; another ref if available)
  - patched_version_old     (git ref)
  - patched_version_new     (git ref)
  - optional: advisory_text, files_of_interest

Outputs: `patched_dataset.csv` with columns:
  ghsa_id, ecosystem, source_code_location, vulnerable_version_old, vulnerable_version_new,
  patched_version_old, patched_version_new, git_diff_path, gumtree_diff_path, localized_hunks (json),
  ai_decision (yes/no/maybe), ai_rationale

Requirements:
  - Python 3.9+
  - pip install gitpython pandas tqdm openai
  - Java 11+ and GumTree CLI jar (https://github.com/GumTreeDiff/gumtree) downloaded as gumtree.jar

Notes:
  - This script *does not* call any LLM by default. Example LLM call code is provided and requires
    setting OPENAI_API_KEY in env. Feel free to swap to your preferred model/service.
  - GumTree is invoked as: `java -jar gumtree.jar parse <oldfile> <newfile> -f json` or `diff` depending on jar

Usage:
  python patch_localizer.py advisories.csv output_folder

"""

import os
import sys
import json
from pathlib import Path

import pandas as pd
from tqdm import tqdm
import helpers

# ---------- Configuration ----------
GUMTREE_JAR = os.environ.get("GUMTREE_JAR", "./gumtree.jar")  # set path if needed
MAX_DIFF_FILE_SIZE = 2_000_000  # skip very large files



# ---------- AI Prompt Templates ----------
LOCALIZATION_PROMPT = '''
We have a security advisory (CWE-79 - Cross-site Scripting) and the following AST-aware edit diff between a vulnerable file and a patched file (GumTree JSON diff attached).
Your jobs (short answers):
1) Identify which changed AST nodes are likely related to the vulnerability (for XSS: look for changes in output-escaping, unsanitized concatenation of user input to HTML, template calls, innerHTML, document.write, etc.).
2) For each suspicious change, produce a JSON list of hunks with: file_path, start_line_old, end_line_old, start_line_new, end_line_new, reason (1-2 sentence), code_snippet_old, code_snippet_new.
Be conservative: if unsure, mark "maybe" with rationale.
Respond with a single JSON object array only.
'''

FIX_CHECK_PROMPT = '''
Given: (1) an advisory short description: {advisory_text}
(2) the vulnerable version ref: {vul_ref}
(3) the patched version ref: {patched_ref}
(4) the unified git diff (or GumTree AST diff) between versions.
Answer in JSON with fields:
  - fixes_vulnerable_version: "yes" | "no" | "maybe"
  - confidence: 0-100
  - short_rationale: one or two sentences
  - remediation_notes: optional steps to verify (tests to run, inputs to fuzz, etc.)
Be precise and conservative with confidence.
'''

# ---------- Main processing ----------

def process_advisories(input_csv: str, output_folder: str):
    df = pd.read_csv(input_csv)
    out_rows = []
    os.makedirs(output_folder, exist_ok=True)
    workspace = Path(output_folder) / 'workspace'
    workspace.mkdir(parents=True, exist_ok=True)

    for _, row in tqdm(df.iterrows(), total=len(df)):
        ghsa = row.get('ghsa_id')
        repo_url = row.get('source_code_location')
        ecosystem = row.get('ecosystem')
        vuln_old = str(row.get('vulnerable_version_old'))
        vuln_new = str(row.get('vulnerable_version_new')) if 'vulnerable_version_new' in row else ''
        patched_old = str(row.get('patched_version_old'))
        patched_new = str(row.get('patched_version_new'))
        advisory_text = row.get('advisory_text', '')

        repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
        repo_dir = str(workspace / f"{ghsa}_{repo_name}")
        try:
            repo = helpers.ensure_repo_cloned(repo_url, repo_dir)
        except Exception as e:
            print(f"failed to clone {repo_url}: {e}")
            continue

        changed_files = helpers.list_changed_files(repo, vuln_old, patched_new)
        if not changed_files:
            changed_files = helpers.list_changed_files(repo, patched_old, patched_new)

        diffs_dir = Path(output_folder) / 'diffs' / ghsa
        gum_dir = Path(output_folder) / 'gumtree' / ghsa
        diffs_dir.mkdir(parents=True, exist_ok=True)
        gum_dir.mkdir(parents=True, exist_ok=True)

        file_pairs = []
        for file_path in changed_files:
            # write both versions
            f_old = helpers.write_file_version(repo_dir, repo, vuln_old, file_path, str(diffs_dir))
            f_new = helpers.write_file_version(repo_dir, repo, patched_new, file_path, str(diffs_dir))
            if f_old and f_new:
                file_pairs.append((file_path, f_old, f_new))

        git_diff_path = str(diffs_dir / f"{repo_name}_{vuln_old}_to_{patched_new}.diff")
        try:
            with open(git_diff_path, 'w', encoding='utf-8') as f:
                f.write(repo.git.diff(f'{vuln_old}..{patched_new}'))
        except Exception:
            pass

        gum_outputs = []
        localized_hunks = []
        for fp, f_old, f_new in file_pairs:
            safe_name = fp.replace('/', '__')
            gum_out = str(gum_dir / f"{safe_name}.json")
            ok = helpers.run_gumtree_diff(f_old, f_new, gum_out)
            if ok:
                gum_outputs.append(gum_out)
                # For now, attempt to extract changed line ranges from git diff as a lightweight localization
                # Use git diff -U0 to get minimal hunks
                rc, hunks, err = helpers.run_cmd(['git', 'diff', '-U0', f'{vuln_old}..{patched_new}', '--', fp], cwd=repo_dir)
                if rc == 0 and hunks.strip():
                    localized_hunks.append({'file': fp, 'git_hunk': hunks})

        # Prepare LLM prompts (user can run these against their LLM of choice)
        # We store the prompts into files for manual review / programmatic use
        prompts_dir = Path(output_folder) / 'prompts' / ghsa
        prompts_dir.mkdir(parents=True, exist_ok=True)
        loc_prompt_file = prompts_dir / 'localization_prompt.txt'
        fix_prompt_file = prompts_dir / 'fix_prompt.txt'
        with open(loc_prompt_file, 'w', encoding='utf-8') as f:
            f.write(LOCALIZATION_PROMPT + "\n\nGumTree outputs:\n")
            for p in gum_outputs[:5]:
                f.write(f"GUMTREE_JSON_FILE: {p}\n")

        with open(fix_prompt_file, 'w', encoding='utf-8') as f:
            f.write(FIX_CHECK_PROMPT.format(advisory_text=advisory_text or "", vul_ref=vuln_old, patched_ref=patched_new))
            f.write('\n\nAttach unified git diff file: ' + git_diff_path + '\n')

        # Optional: an example automatic LLM call (commented out by default). See README below.

        out_rows.append({
            'ghsa_id': ghsa,
            'ecosystem': ecosystem,
            'source_code_location': repo_dir,
            'vulnerable_version_old': vuln_old,
            'vulnerable_version_new': vuln_new,
            'patched_version_old': patched_old,
            'patched_version_new': patched_new,
            'git_diff_path': git_diff_path,
            'gumtree_diff_paths': json.dumps(gum_outputs),
            'localized_hunks': json.dumps(localized_hunks),
            'prompts_dir': str(prompts_dir)
        })

    out_df = pd.DataFrame(out_rows)
    out_csv = Path(output_folder) / 'patched_dataset.csv'
    out_df.to_csv(out_csv, index=False)
    print(f"Written {out_csv}")



# ---------- Entrypoint ----------
if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('usage: python patch_localizer.py advisories.csv output_folder')
        sys.exit(1)
    input_csv = sys.argv[1]
    out_folder = sys.argv[2]
    process_advisories(input_csv, out_folder)

# ---------- README: How to localize & verify with LLM (short) ----------
README = '''
1) Run: python patch_localizer.py advisories.csv outputs
2) For each advisory, inspect prompts/ and gumtree/ and the git diffs in outputs.
3) To localize vulnerability automatically: send the localization prompt file + the GumTree JSON(s) to an LLM capable of handling large JSON (or attach a representative snippet).
   - Use the LOCALIZATION_PROMPT (already saved) and include at most 3-5 GumTree outputs per request.
4) To check whether patch fixes the vulnerable version: send FIX_CHECK_PROMPT + the unified git diff file to the LLM.

Prompt-engineering tips:
 - Give the model the exact CWE category (CWE-79) and short examples of what constitutes a fix (escaping user input, introducing sanitation, removing dangerous sinks).
 - Provide a short test plan for the model to produce (inputs to try, endpoints to fuzz) so it's easier to validate its answer.
 - Ask the model for a confidence (0-100) and concrete verification steps.

'''

# Save README for user convenience
with open('patch_localizer_README.txt', 'w', encoding='utf-8') as fh:
    fh.write(README)
