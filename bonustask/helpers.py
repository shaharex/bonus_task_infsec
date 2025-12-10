import os
import sys
import csv
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Optional

import pandas as pd
from git import Repo, GitCommandError
from tqdm import tqdm


# ---------- Helpers ----------

def run_cmd(cmd: List[str], cwd: Optional[str] = None) -> Tuple[int, str, str]:
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err


def ensure_repo_cloned(repo_url: str, dest: str) -> Repo:
    if os.path.exists(dest) and (Path(dest) / ".git").exists():
        repo = Repo(dest)
        try:
            repo.remote().fetch(tags=True)
        except Exception:
            pass
        return repo
    else:
        return Repo.clone_from(repo_url, dest)


def checkout_ref(repo: Repo, ref: str):
    # Create a temporary branch for this ref to safely inspect files
    g = repo.git
    try:
        g.checkout(ref)
    except GitCommandError:
        # try to fetch and checkout
        repo.remotes.origin.fetch()
        g.checkout(ref)


def list_changed_files(repo: Repo, old_ref: str, new_ref: str) -> List[str]:
    # returns list of paths changed between two refs
    try:
        changed = repo.git.diff('--name-only', f'{old_ref}..{new_ref}').splitlines()
        return [p for p in changed if p]
    except Exception:
        return []


def write_file_version(repo_dir: str, repo: Repo, ref: str, filepath: str, out_root: str) -> Optional[str]:
    # Checkout ref, copy file contents to out_root/ref/<filepath>
    try:
        repo.git.checkout(ref)
    except Exception as e:
        print(f"warning: checkout {ref} failed: {e}")
        return None
    abs = Path(repo_dir) / filepath
    if not abs.exists():
        return None
    size = abs.stat().st_size
    if size > MAX_DIFF_FILE_SIZE:
        print(f"skipping large file {filepath} size={size}")
        return None
    out_path = Path(out_root) / ref / filepath
    out_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(abs, out_path)
    return str(out_path)


def run_gumtree_diff(old_file: str, new_file: str, out_json: str) -> bool:
    # GumTree CLI varies; common invocation is: java -jar gumtree.jar diff old new -f json
    cmd = ["java", "-jar", GUMTREE_JAR, "diff", old_file, new_file, "-f", "json"]
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        # try parse
        cmd2 = ["java", "-jar", GUMTREE_JAR, "parse", old_file, new_file, "-f", "json"]
        rc2, out2, err2 = run_cmd(cmd2)
        if rc2 != 0:
            print(f"gumtree failed: {err}\n{err2}")
            return False
        out = out2
    with open(out_json, 'w', encoding='utf-8') as f:
        f.write(out)
    return True