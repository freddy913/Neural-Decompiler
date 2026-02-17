"""
This script is meant to be run after ObjectToBinary.py has produced linked executables.
It walks the COMPILED/ directory tree, finds every executableN file, extracts the
function names from the corresponding .c source, and creates a TSV worklist of
(binary_path, function_name) pairs. It then spawns --workers parallel processes,
each calling AsmToInput.build_sample() in train mode, writing JSONL pairs into INPUT/.

Usage:
    python generate_training_data.py --compiled-root ./COMPILED --workers 8
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

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

MAX_FILE_BYTES = 2 * 1024 * 1024

_SIMPLE_FUNC_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(", re.MULTILINE)

TASK_TIMEOUT_SECONDS = 60

def _extract_function_names(text):
    """
    Extracts function names from C source text using regex.
    Args:
        :param text: C source code text.
        :return: List of unique function names.
    """

    names = []
    for m in _SIMPLE_FUNC_RE.finditer(text):
        name = m.group(1)
        if name in _C_CONTROL_KEYWORDS:
            continue
        names.append(name)
    return list(dict.fromkeys(names))


def _as_relative(path):
    """
    Converts path to relative POSIX-style with ./ prefix.
    Args:
        :param path: Input file path.
        :return: Relative path string with ./ prefix.
    """

    try:
        rel_path = os.path.relpath(path, start=os.getcwd())
    except ValueError:
        rel_path = os.path.abspath(path)
    if not rel_path.startswith('.'):
        rel_path = f"./{rel_path}"
    return rel_path.replace("\\", "/")

def _to_compiled_binary_path(executable_candidate):
    """
    Translates C_COMPILE path to corresponding COMPILED tree path.
    Args:
        :param executable_candidate: Path in C_COMPILE directory.
        :return: Translated path in COMPILED directory.
    """

    abs_path = os.path.abspath(executable_candidate)
    parts = abs_path.split(os.sep)
    try:
        idx = parts.index("C_COMPILE")
    except ValueError:
        return abs_path
    parts[idx] = "COMPILED"
    return os.sep.join(parts)


def _resolve_binary_path(executable_candidate):
    """
    Resolves compiled binary path with fallback to parent directories.
    Args:
        :param executable_candidate: Path to executable in C_COMPILE tree.
        :return: Tuple of (resolved_path, exists_flag).
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

def _fast_process_file(path):
    """
    Rapidly processes single C file to extract function metadata.
    Args:
        :param path: Absolute path to C source file.
        :return: List of (source_path, executable_path, functions) tuples.
    """

    try:
        size = os.path.getsize(path)
        if MAX_FILE_BYTES and size > MAX_FILE_BYTES:
            return []
    except OSError:
        return []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return []

    if not text:
        return []

    lines = text.splitlines()
    if not lines:
        return []

    first = next((l.strip() for l in lines if l.strip()), "")
    if not (first.startswith("//") or first.startswith("/*")):
        return []

    last = ""
    for l in reversed(lines):
        s = l.strip()
        if s:
            last = s
            break

    if not last or not (last.startswith("//") or last.startswith("/*")):
        return []

    markers = _EXECUTABLE_SUFFIX_RE.findall(last)
    if not markers:
        return []

    funcs = _extract_function_names(text)
    if not funcs:
        return []

    rel = _as_relative(path)
    dirn = os.path.dirname(path)

    results_local = []
    for suf in dict.fromkeys(markers):
        exec_rel = _as_relative(os.path.join(dirn, f"executable{suf}"))
        results_local.append((rel, exec_rel, funcs))

    return results_local

def _iter_source_files(base_dir):
    """
    Iterates over all .c and .h files in directory tree.
    Args:
        :param base_dir: Base directory to scan.
        :return: Generator yielding file paths.
    """

    base_dir = os.path.normpath(base_dir)
    for root, _, files in os.walk(base_dir):
        for name in files:
            if name.endswith((".c", ".h")):
                yield os.path.join(root, name)

def collect_executable_function_metadata(base_dir="./C_COMPILE", workers=None):
    """
    Collects metadata for all executables and their functions in parallel.
    Args:
        :param base_dir: Base directory to scan.
        :param workers: Number of parallel workers or None for auto-detect.
        :return: List of (source_path, exec_path, functions) tuples.
    """

    if not os.path.isdir(base_dir):
        raise FileNotFoundError(base_dir)

    file_iter = _iter_source_files(base_dir)
    results = []

    if workers is None:
        workers = os.cpu_count()

    print(f"[SCAN] using {workers} workers")

    processed = 0
    with mp.Pool(processes=workers) as pool:
        for r in pool.imap_unordered(_fast_process_file, file_iter, chunksize=50):
            processed += 1
            if processed % 1000 == 0:
                print(f"[SCAN] processed {processed} files...", flush=True)
            if r:
                results.extend(r)

    print(f"[SCAN] done. {processed} files processed, {len(results)} metadata entries.")
    return results

def _run_single_task(task):
    """
    Executes single AsmToInput task for one function.
    Args:
        :param task: Tuple of (script_path, binary_path, source_path, function_name).
        :return: Tuple of (function_name, binary_path, success_flag).
    """

    script_path, binary_path, source_path, func = task

    cmd = [
        "python3",
        script_path,
        "--mode", "test",
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
            timeout=TASK_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            print(f"[WARN] failed for {func} ({binary_path}), exit={result.returncode}")
            if result.stderr:
                print(result.stderr)
            return (func, binary_path, False)

        print(f"[OK] {func} ({binary_path})")
        return (func, binary_path, True)
    
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {func} ({binary_path}) exceeded timeout of {TASK_TIMEOUT_SECONDS} seconds")
        return (func, binary_path, False)

    except Exception as exc:
        print(f"[EXCEPTION] {func} ({binary_path}): {exc}")
        return (func, binary_path, False)
    
def _run_binary_task(task):
    """
    Executes batch processing for all functions in one binary using worklist.
    Args:
        :param task: Tuple of (script_path, worklist_path, source_path).
        :return: Tuple of (worklist_path, success_flag).
    """

    script_path, worklist_path, source_path = task

    cmd = [
        "python3",
        script_path,
        "--mode", "test",
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
            timeout=TASK_TIMEOUT_SECONDS, 
        )
        if result.returncode != 0:
            print(f"[WARN] batch failed for worklist={worklist_path}, exit={result.returncode}")
            if result.stderr:
                print(result.stderr)
            return (worklist_path, False)

        print(f"[OK] batch for worklist={worklist_path}")
        return (worklist_path, True)
    
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] batch for worklist={worklist_path} exceeded timeout of {TASK_TIMEOUT_SECONDS} seconds")
        return (worklist_path, False)

    except Exception as exc:
        print(f"[EXCEPTION] batch for worklist={worklist_path}: {exc}")
        return (worklist_path, False)


def _make_worklist_for_binary(binary_path, functions):
    """
    Creates temporary worklist file mapping binary to its functions.
    Args:
        :param binary_path: Path to compiled binary.
        :param functions: List of function names.
        :return: Path to temporary worklist file.
    """
    f = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
    for func in functions:
        f.write(f"{binary_path}\t{func}\n")
    f.close()
    return f.name

def main():
    """
    Main entry point for parallel training data generation.
    Args:
        :return: None.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=0,
                        help="Number of parallel workers (default: env CREATE_TRAIN_WORKERS or all cores)")
    args = parser.parse_args()

    script_path = os.path.join(os.path.dirname(__file__), "AsmToInput.py")

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

    meta = collect_executable_function_metadata(workers=num_workers)
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

    if not tasks:
        print("[INFO] No functions found for training data generation.")
        return


    print(f"[INFO] Prepared {len(tasks)} tasks")
    print(f"[INFO] Using {num_workers} parallel workers\n")

    with mp.Pool(processes=num_workers) as pool:
        results = pool.map(_run_binary_task, tasks)

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
