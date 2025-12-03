import os, re, shlex, subprocess
from pathlib import Path
from typing import List, Tuple

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
    base_dir: str = "/home/freddy/dev/neural-decompiler/Neural-Decompiler/C_COMPILE",
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

def main():
    script_path = os.path.join(os.path.dirname(__file__), "AsmToInput.py")

    for source_path, exec_path, functions in collect_executable_function_metadata():
        if not functions:
            continue

        binary_path, binary_found = _resolve_binary_path(exec_path)
        if not binary_found:
            print(f"[WARN] compiled binary not found for {exec_path}: {binary_path}")
            continue
        expected_path = _to_compiled_binary_path(exec_path)
        if binary_path != expected_path:
            print(f"[INFO] using fallback binary for {exec_path}: {binary_path}")
        for func in functions:
            cmd = [
                "python3",
                script_path,
                "--mode", "train",
                "--binary-path", binary_path,
                "--function-name", func,
                "--source-path", source_path,
                "--UseContext", "true",
            ]
            print(f"[RUN] {' '.join(shlex.quote(part) for part in cmd)}")
            try:
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as exc:
                print(f"[WARN] failed for {func} ({binary_path}): {exc}")

if __name__ == "__main__":
    main()
