#!/usr/bin/env bash
''''true
# ------------------------------------------------------------------------------
# Qoder Privacy Hardening Tool (Ubuntu / Linux)
# Polyglot Launcher: Runs directly with bash, sh, or python3.
# ------------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "[FATAL ERROR] python3 is required to run this tool." >&2
    exit 1
fi
exec python3 "$0" "$@"
'''
# ==============================================================================
# Qoder Privacy Hardening Tool (Linux / Ubuntu Production Hardened)
#
# Hardening Specifications:
#  - Dynamic Qoder path resolution (portable across Linux distros & installs)
#  - Strict fail-closed verification on unknown versions or layout changes
#  - Exact uniqueness constraint (count === 1) on all patch targets
#  - Atomic writes with pre-modification and pre-restore safety backups
#  - Cryptographic verification (SHA256) before and after every transition
#  - Safe privilege elevation detection for system-wide installs (/opt/Qoder)
# ==============================================================================

import os
import sys
import glob
import shutil
import hashlib
import uuid
import subprocess
from datetime import datetime

# ANSI Color Codes
CLR_RESET   = "\033[0m"
CLR_RED     = "\033[91m"
CLR_GREEN   = "\033[92m"
CLR_YELLOW  = "\033[93m"
CLR_CYAN    = "\033[96m"
CLR_WHITE   = "\033[97m"
CLR_GRAY    = "\033[90m"
CLR_BOLD    = "\033[1m"


def clear_screen():
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def print_colored(text, color="", bold=False, end="\n"):
    prefix = ""
    if bold:
        prefix += CLR_BOLD
    if color:
        prefix += color
    suffix = CLR_RESET if prefix else ""
    sys.stdout.write(f"{prefix}{text}{suffix}{end}")
    sys.stdout.flush()


def get_sha256(path):
    if not os.path.isfile(path):
        return ""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().upper()


def resolve_qoder_root():
    candidates = []

    # 1. Environment variable overrides
    if os.environ.get("QODER_PATH"):
        candidates.append(os.environ.get("QODER_PATH"))
    if os.environ.get("QODER_ROOT"):
        candidates.append(os.environ.get("QODER_ROOT"))

    # 2. Binary in PATH (follow symlinks to real installation directory)
    qoder_bin = shutil.which("qoder") or shutil.which("qoder-ai")
    if qoder_bin:
        real_bin = os.path.realpath(qoder_bin)
        candidates.append(os.path.dirname(real_bin))
        candidates.append(os.path.dirname(qoder_bin))

    # 3. Standard Linux installation directories
    home = os.path.expanduser("~")
    candidates.extend([
        "/opt/Qoder",
        "/opt/qoder",
        "/usr/share/qoder",
        "/usr/lib/qoder",
        os.path.join(home, ".local/share/Qoder"),
        os.path.join(home, ".local/share/qoder"),
        os.path.join(home, "Qoder"),
    ])

    for c in candidates:
        if not c:
            continue
        c_real = os.path.realpath(c)
        target_subpath = os.path.join(
            c_real,
            "resources", "app.asar.unpacked", "node_modules",
            "@qoder-ai", "qoder-agent-sdk", "dist", "_worker",
            "qoder-worker-runtime.obf.mjs"
        )
        if os.path.isfile(target_subpath):
            return c_real
        if os.path.isfile(os.path.join(c_real, "qoder")) and os.path.isdir(os.path.join(c_real, "resources")):
            return c_real

    return None


def resolve_qoder_version(root):
    # 1. Try Debian / Ubuntu package database
    try:
        proc = subprocess.run(
            ["dpkg", "-s", "qoder"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.lower().startswith("version:"):
                    ver = line.split(":", 1)[1].strip()
                    if ":" in ver:
                        ver = ver.split(":", 1)[1].strip()
                    return ver
    except Exception:
        pass

    # 2. Try product.json
    prod_json = os.path.join(root, "resources", "product.json")
    if os.path.isfile(prod_json):
        try:
            import json
            with open(prod_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "version" in data:
                    return data["version"]
        except Exception:
            pass

    # 3. Try package.json
    pkg_json = os.path.join(root, "resources", "app", "package.json")
    if os.path.isfile(pkg_json):
        try:
            import json
            with open(pkg_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "version" in data:
                    return data["version"]
        except Exception:
            pass

    return "0.4.3"


# Telemetry Patch Definitions (Identical signatures to Windows specification)
PATCH_DEFS = [
    {
        "id": "vLi",
        "name": "1. businessFinish.report (Prompt Leak)",
        "description": "POST https://api2.qoder.sh/algo/api/v2/service/business/finish",
        "unpatched_sig": "async function vLi(A){let{sessionId:e,businessInfo:t}=A;",
        "replace_target": "async function vLi(A){let{sessionId:e,businessInfo:t}=A;",
        "replace_with": "async function vLi(A){return;let{sessionId:e,businessInfo:t}=A;",
        "patched_sig": "async function vLi(A){return;let{sessionId:e,businessInfo:t}=A;",
    },
    {
        "id": "MTt",
        "name": "2. codeStatistics.track (Code Metrics)",
        "description": "POST https://center.qoder.sh/api/v1/tracking (code metrics)",
        "unpatched_sig": 'MTt=class{constructor(A){this.sender=A}async track(A){await this.sender.send(yi.builder().operation("codeStatistics.track")',
        "replace_target": "MTt=class{constructor(A){this.sender=A}async track(A){",
        "replace_with": "MTt=class{constructor(A){this.sender=A}async track(A){return;",
        "patched_sig": 'MTt=class{constructor(A){this.sender=A}async track(A){return;await this.sender.send(yi.builder().operation("codeStatistics.track")',
    },
    {
        "id": "G$",
        "name": "3. G$ Dispatcher (Git Remote & Metadata)",
        "description": "POST https://center.qoder.sh/api/v1/tracking (git_remote + turn metadata)",
        "unpatched_sig": "async function G$(A){A.beforeSend?.();let e=await Avl",
        "replace_target": "async function G$(A){A.beforeSend?.();let e=await Avl",
        "replace_with": "async function G$(A){A.beforeSend?.();return;let e=await Avl",
        "patched_sig": "async function G$(A){A.beforeSend?.();return;let e=await Avl",
    },
    {
        "id": "tvl",
        "name": "4. tvl Transport (Network Sink)",
        "description": "POST https://center.qoder.sh/api/v1/tracking (transport sink)",
        "unpatched_sig": 'async function tvl(A,e="aiCodeTracking.report",t,i){if(i?.(),!Jd())',
        "replace_target": 'async function tvl(A,e="aiCodeTracking.report",t,i){if(i?.(),!Jd())',
        "replace_with": 'async function tvl(A,e="aiCodeTracking.report",t,i){return;if(i?.(),!Jd())',
        "patched_sig": 'async function tvl(A,e="aiCodeTracking.report",t,i){return;if(i?.(),!Jd())',
    }
]


def evaluate_runtime_state(content):
    results = []
    patched_count = 0
    unpatched_count = 0
    has_ambiguous = False

    for p in PATCH_DEFS:
        c_patched   = content.count(p["patched_sig"])
        c_unpatched = content.count(p["unpatched_sig"])

        if c_patched > 1 or c_unpatched > 1:
            has_ambiguous = True

        is_patched   = (c_patched == 1 and c_unpatched == 0)
        is_unpatched = (c_unpatched == 1 and c_patched == 0)

        if is_patched:
            patched_count += 1
        if is_unpatched:
            unpatched_count += 1

        results.append({
            "id": p["id"],
            "name": p["name"],
            "description": p["description"],
            "is_patched": is_patched,
            "is_unpatched": is_unpatched,
            "patched_count": c_patched,
            "unpatched_count": c_unpatched,
        })

    state = "UNKNOWN"
    if not has_ambiguous:
        if patched_count == 4 and unpatched_count == 0:
            state = "HARDENED"
        elif unpatched_count == 4 and patched_count == 0:
            state = "PRISTINE"
        elif patched_count > 0 or unpatched_count > 0:
            state = "PARTIAL"

    return {
        "state": state,
        "vector_states": results,
        "has_ambiguous": has_ambiguous,
    }


def show_header(qoder_root, qoder_version, target_file):
    clear_screen()
    print_colored("================================================================================", CLR_CYAN, bold=True)
    print_colored("                     QODER PRIVACY HARDENING TOOL v2.0                          ", CLR_CYAN, bold=True)
    print_colored("================================================================================", CLR_CYAN, bold=True)
    print_colored(f"Qoder Root  : {qoder_root}", CLR_GRAY)
    print_colored(f"Qoder Ver   : {qoder_version}", CLR_GRAY)
    print_colored(f"Target File : {target_file}\n", CLR_GRAY)


def ensure_write_permissions(target_dir, target_file, action_name):
    dir_writable = os.access(target_dir, os.W_OK)
    file_writable = os.access(target_file, os.W_OK) if os.path.exists(target_file) else dir_writable

    if dir_writable and file_writable:
        return True

    if os.geteuid() == 0:
        return True

    print_colored(f"\n[ELEVATION REQUIRED] Write permissions needed for: {action_name}", CLR_YELLOW, bold=True)
    print_colored(f"Target directory requires administrative privileges: {target_dir}", CLR_GRAY)

    if sys.stdin.isatty():
        choice = input("Rerun with sudo now? [Y/n]: ").strip().lower()
        if choice in ("", "y", "yes"):
            cmd = ["sudo", sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:]
            try:
                ret = subprocess.call(cmd)
                sys.exit(ret)
            except Exception as e:
                print_colored(f"[FATAL ERROR] Failed to elevate via sudo: {e}", CLR_RED, bold=True)
                sys.exit(1)
        else:
            print_colored("\nOperation cancelled. Please run with sudo:", CLR_YELLOW)
            print_colored(f"  sudo {sys.argv[0]} {' '.join(sys.argv[1:])}\n", CLR_WHITE, bold=True)
            sys.exit(1)
    else:
        print_colored(f"[FATAL ERROR] Root permissions required. Run with:\n  sudo {sys.argv[0]} {' '.join(sys.argv[1:])}", CLR_RED, bold=True)
        sys.exit(1)


def test_privacy_status(qoder_root, qoder_version, target_dir, target_file):
    show_header(qoder_root, qoder_version, target_file)
    print_colored("--- RUNNING PRIVACY VERIFICATION AUDIT ---\n", CLR_YELLOW, bold=True)

    if not os.path.isfile(target_file):
        print_colored("[ERROR] Target runtime file not found:", CLR_RED, bold=True)
        print_colored(f"  {target_file}", CLR_RED)
        print_colored("Status: UNKNOWN VERSION / MISSING RUNTIME\n", CLR_RED, bold=True)
        return 1

    file_size = os.path.getsize(target_file)
    file_hash = get_sha256(target_file)

    with open(target_file, "r", encoding="utf-8") as f:
        content = f.read()

    eval_res = evaluate_runtime_state(content)
    state = eval_res["state"]

    state_color = {
        "HARDENED": CLR_GREEN,
        "PRISTINE": CLR_CYAN,
        "PARTIAL":  CLR_YELLOW,
    }.get(state, CLR_RED)

    print_colored(f"Qoder Version : {qoder_version}", CLR_WHITE)
    print_colored(f"Runtime SHA256: {file_hash}", CLR_WHITE)
    print_colored(f"File Size     : {file_size} bytes", CLR_WHITE)
    print_colored("Runtime State : ", CLR_WHITE, end="")
    print_colored(f"{state}", state_color, bold=True)

    print_colored("\nTelemetry Vector Signatures:", CLR_WHITE)
    print_colored("-" * 80, CLR_GRAY)

    for v in eval_res["vector_states"]:
        if v["is_patched"]:
            status_text = "[PROTECTED / PATCHED]"
            color = CLR_GREEN
        elif v["is_unpatched"]:
            status_text = "[EXPOSED / UNPATCHED]"
            color = CLR_RED
        elif v["patched_count"] > 1 or v["unpatched_count"] > 1:
            status_text = "[AMBIGUOUS SIGNATURE (>1 MATCH)]"
            color = CLR_RED
        else:
            status_text = "[UNRECOGNIZED SIGNATURE]"
            color = CLR_YELLOW

        name_padded = v["name"].ljust(44)
        print_colored(f"{name_padded} : ", CLR_GRAY, end="")
        print_colored(status_text, color, bold=True)
        print_colored(f"   Endpoint: {v['description']}", CLR_GRAY)

    print_colored("-" * 80, CLR_GRAY)

    backups = sorted(
        glob.glob(os.path.join(target_dir, "qoder-worker-runtime.obf.mjs.bak.*")),
        key=os.path.getmtime,
        reverse=True
    )
    safety_backups = glob.glob(os.path.join(target_dir, "qoder-worker-runtime.obf.mjs.safety.*"))
    total_backups = len(backups) + len(safety_backups)

    print_colored(
        f"\nBackups Available: {total_backups} ({len(backups)} rollback point(s), {len(safety_backups)} safety backup(s))",
        CLR_WHITE
    )
    for b in backups[:3]:
        mtime = datetime.fromtimestamp(os.path.getmtime(b)).strftime("%Y-%m-%d %H:%M:%S")
        print_colored(f"  - {os.path.basename(b)} ({mtime})", CLR_GRAY)

    print_colored("\nSummary & Assessment:", CLR_WHITE, bold=True)
    if state == "HARDENED":
        print_colored("[PASS] The known telemetry code paths targeted by this tool are neutralized.", CLR_GREEN, bold=True)
        print_colored("       Runtime network verification is recommended after Qoder updates.", CLR_GREEN)
        return 0
    elif state == "PRISTINE":
        print_colored("[AUDIT] Runtime is in PRISTINE original state. All telemetry code paths are active.", CLR_CYAN, bold=True)
        print_colored("        Run with --apply (or option 3) to apply privacy hardening.", CLR_YELLOW)
        return 0
    elif state == "PARTIAL":
        print_colored("[WARNING] Runtime is partially hardened. Some telemetry signatures are unpatched.", CLR_YELLOW, bold=True)
        print_colored("          Run with --apply (or option 3) to complete hardening.", CLR_YELLOW)
        return 2
    else:
        print_colored("[ERROR] UNSUPPORTED / UNKNOWN VERSION. Runtime signatures do not match known layouts.", CLR_RED, bold=True)
        print_colored("        Tool will fail closed to prevent runtime corruption.", CLR_RED)
        return 1


def dry_run_patch(qoder_root, qoder_version, target_dir, target_file):
    show_header(qoder_root, qoder_version, target_file)
    print_colored("--- RUNNING DRY-RUN SIMULATION (NO DISK MODIFICATIONS) ---\n", CLR_YELLOW, bold=True)

    if not os.path.isfile(target_file):
        print_colored("[FATAL ERROR] Target runtime file not found:", CLR_RED, bold=True)
        print_colored(f"  {target_file}", CLR_RED)
        return 1

    pre_hash = get_sha256(target_file)
    with open(target_file, "r", encoding="utf-8") as f:
        content = f.read()

    eval_res = evaluate_runtime_state(content)
    state = eval_res["state"]

    print_colored(f"Current SHA256 : {pre_hash}", CLR_WHITE)
    print_colored(f"Current State  : {state}\n", CLR_WHITE, bold=True)

    if state == "HARDENED":
        print_colored("[INFO] All 4 patches are ALREADY applied. Runtime is already HARDENED.", CLR_GREEN, bold=True)
        return 0

    if eval_res["has_ambiguous"]:
        print_colored("[DRY-RUN FAILED] Ambiguous signatures detected in runtime file.", CLR_RED, bold=True)
        print_colored("One or more targets matched multiple locations. Real patch would fail-closed.", CLR_RED)
        return 1

    if state not in ("PRISTINE", "PARTIAL"):
        print_colored("[DRY-RUN FAILED] UNSUPPORTED / UNKNOWN VERSION.", CLR_RED, bold=True)
        return 1

    # Check uniqueness of all targets
    print_colored("1. Validating Signature Uniqueness Constraints:", CLR_WHITE, bold=True)
    all_valid = True
    for p in PATCH_DEFS:
        c_patched = content.count(p["patched_sig"])
        c_unpatched = content.count(p["unpatched_sig"])
        c_target = content.count(p["replace_target"])

        if c_patched == 0:
            if c_unpatched == 1 and c_target == 1:
                print_colored(f"   [OK] {p['id']} - Exactly 1 unpatched match found.", CLR_GREEN)
            else:
                print_colored(
                    f"   [FAIL] {p['id']} - Expected 1 match, found: unpatched={c_unpatched}, target={c_target}",
                    CLR_RED
                )
                all_valid = False
        else:
            print_colored(f"   [SKIP] {p['id']} - Already patched (1 occurrence).", CLR_GRAY)

    if not all_valid:
        print_colored("\n[DRY-RUN FAILED] Signature validation failed. Apply would abort safely.", CLR_RED, bold=True)
        return 1

    # Backup logic simulation
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    simulated_backup = f"{target_file}.bak.{timestamp}"
    print_colored(f"\n2. Simulating Pre-patch Backup Step:", CLR_WHITE, bold=True)
    print_colored(f"   Destination : {simulated_backup}", CLR_CYAN)
    print_colored(f"   Validation  : Real apply calculates SHA256 of backup and verifies against pre-hash ({pre_hash})", CLR_GRAY)
    
    dir_writable = os.access(target_dir, os.W_OK)
    file_writable = os.access(target_file, os.W_OK)
    if dir_writable and file_writable:
        print_colored("   Permissions : Directory and file are writable by current user.", CLR_GREEN)
    else:
        print_colored("   Permissions : Write access requires sudo (apply will auto-prompt for elevation).", CLR_YELLOW)

    # In-memory patch simulation
    print_colored(f"\n3. Simulating Surgical Patch Operations (In-Memory):", CLR_WHITE, bold=True)
    new_content = content
    for p in PATCH_DEFS:
        c_patched = new_content.count(p["patched_sig"])
        if c_patched == 0:
            idx = new_content.find(p["replace_target"])
            if idx == -1:
                print_colored(f"   [FAIL] Target lost for {p['id']}!", CLR_RED)
                return 1
            new_content = (
                new_content[:idx]
                + p["replace_with"]
                + new_content[idx + len(p["replace_target"]):]
            )
            print_colored(f"   [SIMULATED PATCH] {p['name']}", CLR_GREEN)
        else:
            print_colored(f"   [ALREADY PATCHED] {p['name']}", CLR_GRAY)

    # In-memory post-evaluation
    sim_hasher = hashlib.sha256()
    sim_hasher.update(new_content.encode("utf-8"))
    sim_post_hash = sim_hasher.hexdigest().upper()

    post_eval = evaluate_runtime_state(new_content)
    print_colored(f"\n4. Simulating Post-Patch Audit Verification:", CLR_WHITE, bold=True)
    print_colored(f"   Simulated Post-Patch SHA256: {sim_post_hash}", CLR_WHITE)
    print_colored(f"   Simulated Runtime State    : {post_eval['state']}", CLR_GREEN, bold=True)

    if post_eval["state"] != "HARDENED":
        print_colored("\n[DRY-RUN FAILED] Simulated state did not reach HARDENED!", CLR_RED, bold=True)
        return 1

    print_colored("\n" + "=" * 80, CLR_GREEN)
    print_colored("[DRY-RUN SUCCESS] All checks passed cleanly!", CLR_GREEN, bold=True)
    print_colored("  * Pre-patch backups verified & guaranteed prior to any write.", CLR_GREEN)
    print_colored("  * All 4 telemetry signatures match with exact uniqueness (count == 1).", CLR_GREEN)
    print_colored("  * Post-patch evaluation reaches 100% HARDENED state.", CLR_GREEN)
    print_colored("  * NO live files were modified in this dry-run.", CLR_CYAN, bold=True)
    print_colored("=" * 80 + "\n", CLR_GREEN)
    return 0


def apply_privacy_patch(qoder_root, qoder_version, target_dir, target_file):
    ensure_write_permissions(target_dir, target_file, "apply patch")
    show_header(qoder_root, qoder_version, target_file)
    print_colored("--- APPLYING PRIVACY HARDENING PATCHES ---\n", CLR_YELLOW, bold=True)

    if not os.path.isfile(target_file):
        print_colored("[FATAL ERROR] Target runtime file not found:", CLR_RED, bold=True)
        print_colored(f"  {target_file}", CLR_RED)
        return 1

    pre_hash = get_sha256(target_file)
    with open(target_file, "r", encoding="utf-8") as f:
        content = f.read()

    eval_res = evaluate_runtime_state(content)
    state = eval_res["state"]

    if state == "HARDENED":
        print_colored("[INFO] All 4 patches are ALREADY applied. Runtime is already in HARDENED state.", CLR_GREEN, bold=True)
        print_colored(f"Current SHA256: {pre_hash}", CLR_WHITE)
        return 0

    if eval_res["has_ambiguous"]:
        print_colored("[FATAL ERROR] Ambiguous signatures detected in runtime file.", CLR_RED, bold=True)
        print_colored("One or more targets matched multiple locations. Failing closed without changes.", CLR_RED)
        return 1

    if state not in ("PRISTINE", "PARTIAL"):
        print_colored("[FATAL ERROR] UNSUPPORTED / UNKNOWN VERSION", CLR_RED, bold=True)
        print_colored("Runtime layout does not match known Qoder engine signatures.", CLR_RED)
        print_colored("File has NOT been modified.", CLR_RED)
        return 1

    # Strict fail-closed verification: each unpatched target must occur EXACTLY once
    for p in PATCH_DEFS:
        c_patched = content.count(p["patched_sig"])
        if c_patched == 0:
            c_unpatched = content.count(p["unpatched_sig"])
            c_target    = content.count(p["replace_target"])
            if c_unpatched != 1 or c_target != 1:
                print_colored(f"[FATAL ERROR] Signature mismatch for target '{p['id']}'.", CLR_RED, bold=True)
                print_colored(
                    f"Expected exactly 1 occurrence, found: unpatched={c_unpatched}, replaceTarget={c_target}.",
                    CLR_RED
                )
                print_colored("Failing closed. File has NOT been modified.", CLR_RED)
                return 1

    # Step 1: Create atomic pre-patch backup BEFORE any modifications
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"{target_file}.bak.{timestamp}"

    print_colored("Creating pre-patch backup...", CLR_WHITE)
    try:
        with open(backup_file, "w", encoding="utf-8") as f:
            f.write(content)
        orig_mode = os.stat(target_file).st_mode
        os.chmod(backup_file, orig_mode)
    except Exception as e:
        print_colored(f"[FATAL ERROR] Failed to write backup: {e}", CLR_RED, bold=True)
        return 1

    backup_hash = get_sha256(backup_file)
    if backup_hash != pre_hash:
        print_colored("[FATAL ERROR] Backup verification failed! Hash mismatch.", CLR_RED, bold=True)
        if os.path.exists(backup_file):
            os.remove(backup_file)
        return 1

    print_colored(f"[BACKUP VERIFIED] {os.path.basename(backup_file)} (SHA256: {backup_hash})", CLR_CYAN, bold=True)

    # Step 2: Apply surgical patches strictly to verified targets
    new_content = content
    for p in PATCH_DEFS:
        c_patched = new_content.count(p["patched_sig"])
        if c_patched == 0:
            idx = new_content.find(p["replace_target"])
            if idx == -1:
                print_colored(f"[FATAL ERROR] Target string lost during sequential patch for {p['id']}!", CLR_RED, bold=True)
                return 1
            new_content = (
                new_content[:idx]
                + p["replace_with"]
                + new_content[idx + len(p["replace_target"]):]
            )
            print_colored(f"[PATCH APPLIED] {p['name']}", CLR_GREEN, bold=True)
        else:
            print_colored(f"[ALREADY PATCHED] {p['name']}", CLR_GRAY)

    # Step 3: Write atomically to temporary file, then swap
    temp_file = f"{target_file}.tmp.{uuid.uuid4().hex}"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(new_content)
        os.chmod(temp_file, orig_mode)
        os.replace(temp_file, target_file)
    except Exception as e:
        print_colored(f"[FATAL ERROR] Failed to write updated file: {e}", CLR_RED, bold=True)
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return 1

    # Step 4: Strict post-patch verification
    post_hash = get_sha256(target_file)
    with open(target_file, "r", encoding="utf-8") as f:
        post_content = f.read()

    post_eval = evaluate_runtime_state(post_content)
    if post_eval["state"] != "HARDENED":
        print_colored("[CRITICAL ERROR] Post-patch validation failed! Runtime is not HARDENED.", CLR_RED, bold=True)
        print_colored("Restoring pre-patch backup immediately...", CLR_YELLOW, bold=True)
        shutil.copy2(backup_file, target_file)
        reverted_hash = get_sha256(target_file)
        print_colored(f"Restored original runtime file (SHA256: {reverted_hash}).", CLR_YELLOW)
        return 1

    print_colored("\n[SUCCESS] Privacy hardening successfully applied and verified.", CLR_GREEN, bold=True)
    print_colored(f"Pre-patch SHA256 : {pre_hash}", CLR_WHITE)
    print_colored(f"Post-patch SHA256: {post_hash}", CLR_GREEN, bold=True)
    print_colored(f"Backup preserved : {os.path.basename(backup_file)}", CLR_WHITE)
    print_colored("[NOTE] Please restart Qoder (or run Developer: Reload Window) for changes to take effect.\n", CLR_YELLOW, bold=True)
    return 0


def restore_backup(qoder_root, qoder_version, target_dir, target_file):
    ensure_write_permissions(target_dir, target_file, "restore backup")
    show_header(qoder_root, qoder_version, target_file)
    print_colored("--- RESTORING FROM PREVIOUS BACKUP ---\n", CLR_YELLOW, bold=True)

    if not os.path.isdir(target_dir):
        print_colored("[ERROR] Target runtime directory not accessible.", CLR_RED, bold=True)
        return 1

    backups = sorted(
        glob.glob(os.path.join(target_dir, "qoder-worker-runtime.obf.mjs.bak.*")),
        key=os.path.getmtime,
        reverse=True
    )
    if not backups:
        print_colored(f"[ERROR] No rollback backup files found in {target_dir}", CLR_RED, bold=True)
        return 1

    selected_backup = backups[0]
    print_colored(f"Available Backups ({len(backups)}): ", CLR_WHITE)
    for i, b in enumerate(backups[:5]):
        marker = " [LATEST - WILL RESTORE]" if i == 0 else ""
        mtime = datetime.fromtimestamp(os.path.getmtime(b)).strftime("%Y-%m-%d %H:%M:%S")
        print_colored(f"  [{i}] {os.path.basename(b)} ({mtime}){marker}", CLR_GRAY)

    mtime_sel = datetime.fromtimestamp(os.path.getmtime(selected_backup)).strftime("%Y-%m-%d %H:%M:%S")
    backup_hash = get_sha256(selected_backup)

    print_colored("\nSelected Backup to Restore:", CLR_WHITE, bold=True)
    print_colored(f"  Name     : {os.path.basename(selected_backup)}", CLR_CYAN)
    print_colored(f"  Path     : {selected_backup}", CLR_CYAN)
    print_colored(f"  Modified : {mtime_sel}", CLR_CYAN)
    print_colored(f"  SHA256   : {backup_hash}", CLR_CYAN)

    current_hash = get_sha256(target_file)
    safety_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safety_backup = f"{target_file}.safety.{safety_timestamp}"

    print_colored("\nCreating pre-restore safety backup...", CLR_WHITE)
    try:
        shutil.copy2(target_file, safety_backup)
    except Exception as e:
        print_colored(f"[FATAL ERROR] Safety backup creation failed: {e}", CLR_RED, bold=True)
        return 1

    safety_hash = get_sha256(safety_backup)
    if safety_hash != current_hash:
        print_colored("[FATAL ERROR] Safety backup verification failed! Aborting restore.", CLR_RED, bold=True)
        if os.path.exists(safety_backup):
            os.remove(safety_backup)
        return 1

    print_colored(f"[SAFETY BACKUP VERIFIED] {os.path.basename(safety_backup)} (SHA256: {safety_hash})", CLR_CYAN, bold=True)

    temp_restore = f"{target_file}.tmp.restore.{uuid.uuid4().hex}"
    try:
        shutil.copy2(selected_backup, temp_restore)
        os.replace(temp_restore, target_file)
    except Exception as e:
        print_colored(f"[FATAL ERROR] Restore copy failed: {e}", CLR_RED, bold=True)
        if os.path.exists(temp_restore):
            os.remove(temp_restore)
        return 1

    restored_hash = get_sha256(target_file)
    if restored_hash != backup_hash:
        print_colored("[CRITICAL ERROR] Restored file hash does not match backup hash!", CLR_RED, bold=True)
        print_colored("Reverting to pre-restore safety backup...", CLR_YELLOW, bold=True)
        shutil.copy2(safety_backup, target_file)
        return 1

    print_colored("\n[SUCCESS] Runtime successfully restored from backup.", CLR_GREEN, bold=True)
    print_colored(f"Restored SHA256: {restored_hash}", CLR_GREEN, bold=True)
    print_colored(f"Safety backup  : {os.path.basename(safety_backup)}\n", CLR_WHITE)
    return 0


def main():
    qoder_root = resolve_qoder_root()
    if not qoder_root:
        print_colored("[FATAL ERROR] Could not locate Qoder installation.", CLR_RED, bold=True)
        print_colored("Expected location: /opt/Qoder or in system PATH.", CLR_RED)
        print_colored("You may set QODER_PATH=/path/to/qoder environment variable.", CLR_GRAY)
        sys.exit(1)

    qoder_version = resolve_qoder_version(qoder_root)
    target_dir = os.path.join(
        qoder_root,
        "resources", "app.asar.unpacked", "node_modules",
        "@qoder-ai", "qoder-agent-sdk", "dist", "_worker"
    )
    target_file = os.path.join(target_dir, "qoder-worker-runtime.obf.mjs")

    mode = sys.argv[1] if len(sys.argv) > 1 else ""

    if mode in ("--test", "-t"):
        code = test_privacy_status(qoder_root, qoder_version, target_dir, target_file)
        sys.exit(code)
    elif mode in ("--dry-run", "-d"):
        code = dry_run_patch(qoder_root, qoder_version, target_dir, target_file)
        sys.exit(code)
    elif mode in ("--apply", "-a"):
        code = apply_privacy_patch(qoder_root, qoder_version, target_dir, target_file)
        sys.exit(code)
    elif mode in ("--restore", "-r"):
        code = restore_backup(qoder_root, qoder_version, target_dir, target_file)
        sys.exit(code)
    elif mode in ("--help", "-h"):
        print_colored(f"Qoder Privacy Hardening Tool v2.0 (Ubuntu / Linux)", CLR_CYAN, bold=True)
        print("\nUsage:")
        print("  ./apply-qoder-privacy-patch.sh [option]\n")
        print("Options:")
        print("  -t, --test     Test and audit current privacy hardening status (read-only)")
        print("  -d, --dry-run  Simulate patch application & backup logic without modifying files")
        print("  -a, --apply    Apply privacy hardening patches (auto-backup)")
        print("  -r, --restore  Restore runtime from latest backup")
        print("  -h, --help     Show this help message\n")
        print("Interactive Mode:")
        print("  Run without options to enter interactive menu.")
        sys.exit(0)

    while True:
        show_header(qoder_root, qoder_version, target_file)
        print_colored("Choose an action:", CLR_WHITE, bold=True)
        print_colored("  [1] Test / Verify privacy hardening status", CLR_WHITE)
        print_colored("  [2] Dry-run simulation (validate patches & backup logic without modifying files)", CLR_WHITE)
        print_colored("  [3] Apply privacy hardening patches (auto-backup)", CLR_WHITE)
        print_colored("  [4] Restore from latest backup (with pre-restore safety snapshot)", CLR_WHITE)
        print_colored("  [5] Exit\n", CLR_WHITE)

        try:
            choice = input("Select option [1-5]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

        if choice == "1":
            test_privacy_status(qoder_root, qoder_version, target_dir, target_file)
            input("\nPress Enter to continue...")
        elif choice == "2":
            dry_run_patch(qoder_root, qoder_version, target_dir, target_file)
            input("\nPress Enter to continue...")
        elif choice == "3":
            apply_privacy_patch(qoder_root, qoder_version, target_dir, target_file)
            input("\nPress Enter to continue...")
        elif choice == "4":
            restore_backup(qoder_root, qoder_version, target_dir, target_file)
            input("\nPress Enter to continue...")
        elif choice in ("5", "q", "exit"):
            sys.exit(0)
        else:
            print_colored("Invalid option.", CLR_RED)


if __name__ == "__main__":
    main()
