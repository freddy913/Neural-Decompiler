#!/usr/bin/env python3
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import List, Tuple
import multiprocessing as mp  
import tempfile
import argparse

_EXECUTABLE_SUFFIX_RE = re.compile(r"executable(\d+)", re.IGNORECASE)
_FUNCTION_DEF_RE = re.compile(
    r"""
    ^\s*
    (?:[A-Za-z_]\w*\s+)*           # qualifiers and return type tokens
    (?:\*+\s*)*                    # pointer stars that belong to the return type
    ([A-Za-z_]\w*)                 # function name
    \s*\(
        [^;{}]*                    # parameter list without braces or semicolons
    \)
    (?:\s*__attribute__\s*\(\([^)]*\)\))*  # optional GCC-style attributes
    \s*\{
    """,
    re.MULTILINE | re.VERBOSE,
)

_C_CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "case",
    "return",
    "sizeof",
    "else",
    "do",
}


def _as_relative(path: str) -> str:
    """Return a ./-prefixed, POSIX-style relative path for consistent downstream use."""
    try:
        rel_path = os.path.relpath(path, start=os.getcwd())
    except ValueError:
        rel_path = os.path.abspath(path)
    if not rel_path.startswith('.'):
        rel_path = f"./{rel_path}"
    return rel_path.replace("\\", "/")


def _to_compiled_binary_path(executable_candidate: str) -> str:
    """Translate a discovered C_COMPILE executable path into the COMPILED tree."""
    abs_path = os.path.abspath(executable_candidate)
    parts = abs_path.split(os.sep)
    try:
        idx = parts.index("C_COMPILE")
    except ValueError:
        return abs_path
    parts[idx] = "COMPILED"
    return os.sep.join(parts)


def _resolve_binary_path(executable_candidate: str) -> Tuple[str, bool]:
    """
    Return (path, exists) for the compiled binary corresponding to executable_candidate.

    Falls back to higher-level directories if the compiled tree does not mirror the source tree.
    """
    primary = _to_compiled_binary_path(executable_candidate)
    primary_path = Path(primary)
    if primary_path.exists():
        return str(primary_path), True

    try:
        compiled_idx = primary_path.parts.index("COMPILED")
    except ValueError:
        return str(primary_path), False

    filename = primary_path.name
    base = Path(*primary_path.parts[: compiled_idx + 1])
    suffix = primary_path.parts[compiled_idx + 1 : -1]

    for cut in range(len(suffix) - 1, -1, -1):
        candidate = base.joinpath(*suffix[:cut], filename)
        if candidate.exists():
            return str(candidate), True

    return str(primary_path), False


def collect_executable_function_metadata(
    base_dir: str = "./C_COMPILE",
) -> List[Tuple[str, str, List[str]]]:
    """
    Traverse repositories in base_dir and extract function metadata for executable-tagged files.

    Returns a list of tuples in the form:
        (source_path, executable_marker_path, [function_names...])
    """
    results: List[Tuple[str, str, List[str]]] = []
    normalized_base = os.path.normpath(base_dir)

    if not os.path.isdir(normalized_base):
        raise FileNotFoundError(f"Base directory not found: {base_dir}")

    for root, _, files in os.walk(normalized_base):
        for filename in files:
            if not filename.endswith((".c", ".h")):
                continue

            file_path = os.path.join(root, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                    file_content = handle.read()
            except OSError:
                continue

            if not file_content:
                continue

            lines = file_content.splitlines()
            if not lines:
                continue

            first_significant = next((line.strip() for line in lines if line.strip()), "")
            if not (first_significant.startswith("//") or first_significant.startswith("/*")):
                continue

            last_significant = ""
            for line in reversed(lines):
                stripped = line.strip()
                if stripped:
                    last_significant = stripped
                    break

            if not last_significant or not (
                last_significant.startswith("//") or last_significant.startswith("/*")
            ):
                continue

            marker_suffixes = _EXECUTABLE_SUFFIX_RE.findall(last_significant)
            if not marker_suffixes:
                continue

            source_rel_path = _as_relative(file_path)
            function_names = []
            for match in _FUNCTION_DEF_RE.finditer(file_content):
                candidate = match.group(1)
                if candidate in _C_CONTROL_KEYWORDS:
                    continue
                function_names.append(candidate)

            seen = set()
            ordered_function_names: List[str] = []
            for name in function_names:
                if name not in seen:
                    seen.add(name)
                    ordered_function_names.append(name)

            for suffix in dict.fromkeys(marker_suffixes):
                executable_rel_path = _as_relative(
                    os.path.join(os.path.dirname(file_path), f"executable{suffix}")
                )
                results.append((source_rel_path, executable_rel_path, ordered_function_names))

    return results


# -------------------------------------------------------------------
# NEU: Worker-Funktion für einen einzelnen AsmToInput-Aufruf
# -------------------------------------------------------------------
def _run_single_task(task):
    """
    task: (script_path, binary_path, source_path, func_name)

    Führt:
      python3 AsmToInput.py --mode train --binary-path ... --function-name ... --source-path ... --UseContext true
    aus und gibt (func_name, binary_path, success_bool) zurück.
    """
    script_path, binary_path, source_path, func = task

    cmd = [
        "python3",
        script_path,
        "--mode", "train",
        "--binary-path", binary_path,
        "--function-name", func,
        "--source-path", source_path,
        "--UseContext", "true",
    ]

    pretty_cmd = " ".join(shlex.quote(part) for part in cmd)
    print(f"[RUN] {pretty_cmd}")

    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            print(f"[WARN] failed for {func} ({binary_path}), exit={result.returncode}")
            if result.stderr:
                print(result.stderr)
            return (func, binary_path, False)

        # Optional: stdout silencing oder logging:
        # if result.stdout:
        #     print(result.stdout)

        print(f"[OK] {func} ({binary_path})")
        return (func, binary_path, True)

    except Exception as exc:
        print(f"[EXCEPTION] {func} ({binary_path}): {exc}")
        return (func, binary_path, False)
    
def _run_binary_task(task):
    """
    task: (script_path, worklist_path, source_path)

    Ruft:
      python3 AsmToInput.py --mode train --batch --worklist ... --source-path ... --UseContext true
    auf und lässt AsmToInput alle Funktionen aus der Worklist abarbeiten.
    """
    script_path, worklist_path, source_path = task

    cmd = [
        "python3",
        script_path,
        "--mode", "train",
        "--batch",
        "--worklist", worklist_path,
        "--UseContext", "true",
        "--source-path", source_path,
    ]

    pretty_cmd = " ".join(shlex.quote(part) for part in cmd)
    print(f"[RUN BINARY] {pretty_cmd}")

    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            print(f"[WARN] batch failed for worklist={worklist_path}, exit={result.returncode}")
            if result.stderr:
                print(result.stderr)
            return (worklist_path, False)

        print(f"[OK] batch for worklist={worklist_path}")
        return (worklist_path, True)

    except Exception as exc:
        print(f"[EXCEPTION] batch for worklist={worklist_path}: {exc}")
        return (worklist_path, False)


def _make_worklist_for_binary(binary_path, functions):
    f = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
    for func in functions:
        f.write(f"{binary_path}\t{func}\n")
    f.close()
    return f.name

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=0,
                        help="Number of parallel workers (default: env CREATE_TRAIN_WORKERS or all cores)")
    args = parser.parse_args()

    script_path = os.path.join(os.path.dirname(__file__), "AsmToInput.py")

    meta = collect_executable_function_metadata()
    tasks = []

    for source_path, exec_path, functions in meta:
        if not functions:
            continue

        binary_path, binary_found = _resolve_binary_path(exec_path)
        if not binary_found:
            print(f"[WARN] compiled binary not found for {exec_path}: {binary_path}")
            continue

        expected_path = _to_compiled_binary_path(exec_path)
        if binary_path != expected_path:
            print(f"[INFO] using fallback binary for {exec_path}: {binary_path}")

        worklist_path = _make_worklist_for_binary(binary_path, functions)
        tasks.append((script_path, worklist_path, source_path))
        # for func in functions:
        #     tasks.append((script_path, binary_path, source_path, func))

    if not tasks:
        print("[INFO] No functions found for training data generation.")
        return

    # Anzahl Worker: entweder aus ENV oder alle Cores
    try:
        env_workers = int(os.environ.get("CREATE_TRAIN_WORKERS", "0"))
    except ValueError:
        env_workers = 0

    if args.workers > 0:
        num_workers = args.workers
    elif env_workers > 0:
        num_workers = env_workers
    else:
        num_workers = mp.cpu_count()

    print(f"[INFO] Prepared {len(tasks)} tasks")
    print(f"[INFO] Using {num_workers} parallel workers\n")

    # Multiprocessing-Pool starten
    with mp.Pool(processes=num_workers) as pool:
        # results = pool.map(_run_single_task, tasks)
        results = pool.map(_run_binary_task, tasks)

    # Zusammenfassung
    print("\n================ SUMMARY ================")
    ok_count = 0
    fail_count = 0
    for worklist_path, success in results:
        status = "OK" if success else "FAIL"
        print(f"{worklist_path:<40} {status}  ({binary_path})")
        if success:
            ok_count += 1
        else:
            fail_count += 1

    print("=========================================")
    print(f"Total: {len(results)}, OK: {ok_count}, FAIL: {fail_count}")
    print("=========================================\n")


if __name__ == "__main__":
    main()
