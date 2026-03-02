"""
Streamlit Demo for the Neural Decompiler.
Run with:  streamlit run demo/demo.py
"""
import sys
import os
import re
import tempfile
import json
import subprocess

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import torch

st.set_page_config(page_title="Neural Decompiler", layout="wide")
st.title("Neural Decompilation Demo")
st.markdown(
    "Upload an **ELF binary** or scrape C files from a **GitHub repo**, "
    "then let the LongT5-based model generate C source code from the assembly."
)

from pipeline.ElfFeatures import load_project, get_function_assembly, collect_constant_pool_for_function
from pipeline.AsmToInput import build_sample
from pipeline.Heuristic import is_relevant_user_like_function
from pipeline.Config import JUNK_FUNCTIONS


MODEL_ID = "freddy913/FRDYV2_35"
MAX_SOURCE_LENGTH = 8192
MAX_NEW_TOKENS = 1024


@st.cache_resource(show_spinner="Loading LongT5 model …")
def load_model():
    from transformers import AutoTokenizer, LongT5ForConditionalGeneration

    device = "cuda" if torch.cuda.is_available() else "cpu"
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    model = LongT5ForConditionalGeneration.from_pretrained(
        MODEL_ID,
        torch_dtype=torch.bfloat16 if device == "cuda" else torch.float32,
        low_cpu_mem_usage=True,
    ).to(device)
    model.tie_weights()
    model.encoder.embed_tokens = model.shared
    model.decoder.embed_tokens = model.shared
    model.eval()
    return tokenizer, model, device


def reconstruct_literals(c_code, constant_pool):
    if not c_code or not constant_pool:
        return c_code
    sorted_items = sorted(
        constant_pool.values(),
        key=lambda x: len(x.get("placeholder", "")),
        reverse=True,
    )
    for item in sorted_items:
        ph = item.get("placeholder")
        txt = item.get("text")
        if ph and txt and ph in c_code:
            c_code = c_code.replace(ph, json.dumps(txt))
    return c_code


def extract_function_from_source(source: str, func_name: str) -> str | None:
    """Extract a single C function definition from *source* by name.

    Uses a simple brace-counting heuristic: find a line that looks like the
    start of *func_name*, then collect everything until the braces balance.
    Returns the function text, or None if not found.
    """
    pattern = re.compile(
        rf'\b{re.escape(func_name)}\s*\(', re.MULTILINE
    )
    lines = source.splitlines(keepends=True)
    start_line = None
    for i, line in enumerate(lines):
        # Skip lines that are pure declarations (end with ';') or preprocessor
        if pattern.search(line) and not line.rstrip().endswith(";"):
            # Walk backwards to include return type / qualifiers
            start_line = i
            while start_line > 0 and "{" not in lines[start_line]:
                start_line -= 1
                if lines[start_line].strip() == "" or lines[start_line].lstrip().startswith("#"):
                    start_line += 1
                    break
            break
    if start_line is None:
        return None

    depth = 0
    body_started = False
    func_lines = []
    for line in lines[start_line:]:
        func_lines.append(line)
        depth += line.count("{") - line.count("}")
        if "{" in line:
            body_started = True
        if body_started and depth <= 0:
            break
    return "".join(func_lines).rstrip("\n") if func_lines else None


# ── GitHub scraping helpers 
GITHUB_API = "https://api.github.com"
_REPO_URL_RE = re.compile(
    r"(?:https?://)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$"
)


def parse_github_url(url: str):
    """Extract (owner, repo) from a GitHub URL, or return None."""
    m = _REPO_URL_RE.match(url.strip())
    if m:
        return m.group(1), m.group(2)
    return None


def _walk_github_tree(owner, repo, path="", headers=None):
    """Recursively list .c files in a GitHub repo via the Contents API."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code != 200:
        return []
    items = resp.json()
    if not isinstance(items, list):
        return []
    c_files = []
    for item in items:
        if item["type"] == "file" and item["name"].endswith(".c"):
            c_files.append(item)
        elif item["type"] == "dir":
            c_files.extend(
                _walk_github_tree(owner, repo, item["path"], headers)
            )
    return c_files


@st.cache_data(show_spinner="Fetching C files from GitHub …", ttl=60)
def fetch_c_files_from_repo(owner, repo, token=None):
    """Return list of dicts with 'name', 'path', 'download_url'."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return _walk_github_tree(owner, repo, headers=headers)


def compile_c_to_binary(c_source: str, filename: str, work_dir: str):
    """Compile a C source string to an ELF binary. Returns path or None."""
    src_path = os.path.join(work_dir, filename)
    bin_path = os.path.join(work_dir, filename.replace(".c", ""))
    with open(src_path, "w", encoding="utf-8") as f:
        f.write(c_source)
    result = subprocess.run(
        ["gcc", "-O0", "-g", "-o", bin_path, src_path],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode == 0 and os.path.isfile(bin_path):
        return bin_path
    return None


def _get_objdump_for_function(binary_path: str, func_name: str) -> str | None:
    """Run objdump -d and extract the disassembly for a single function."""
    try:
        result = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", binary_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
    except Exception:
        return None

    lines = result.stdout.splitlines()
    collecting = False
    func_lines = []
    header_re = re.compile(rf"<{re.escape(func_name)}>:\s*$")

    for line in lines:
        if not collecting:
            if header_re.search(line):
                collecting = True
                func_lines.append(line)
        else:
            if line.strip() == "":
                break
            func_lines.append(line)

    return "\n".join(func_lines) if func_lines else None


# ── Sidebar: settings
st.sidebar.header("Pipeline (Preprocessing)")
context_mode = st.sidebar.radio(
    "Context-Mode",
    ["Heuristic BFS Context", "No Context (Isolated Function)"],
    index=0,
    help="'Heuristic BFS Context' adds Caller/Callee-Functions as Context. "
         "'No Context' returns just the isolated Target Function to the model.",
)
st.sidebar.markdown("**Normalization Level**")
norm_strip_sizes = st.sidebar.checkbox(
    "Strip Operand Sizes (DWORD PTR)", value=True,
    help="Removes operand size qualifiers like `dword ptr`, `qword ptr` etc. from the assembly.",
)
norm_abstract_strings = st.sidebar.checkbox(
    "Abstract Strings to Constant Pool (STRx…)", value=True,
    help="Replaces RIP-relative string references with placeholders like STR0, FMT1 etc. The original strings are stored in the constant pool and reconstructed in the final C code.",
)

st.sidebar.markdown("---")
st.sidebar.header("Display")
show_objdump = st.sidebar.checkbox(
    "Show objdump disassembly", value=False,
    help="Show raw objdump output alongside the angr disassembly for comparison.",
)

st.sidebar.markdown("---")
st.sidebar.header("Decoder")
rep_penalty = st.sidebar.slider(
    "Repetition Penalty", 1.0, 2.0, 1.2, 0.1,
    help="Penalizes repeated tokens. At 1.0, code is often buggy (e.g. bitwise ops turn into %%). At 1.2, output is cleaner.",
)
temperature = st.sidebar.slider(
    "Temperature", 0.0, 1.0, 0.0, 0.05,
    help="Controls randomness of the output. 0.0 = deterministic (greedy). Higher values make the output more random — the model starts inventing variable names.",
)

def analyse_and_decompile(binary_path: str, display_name: str,
                          original_source: str | None = None):
    """Load binary with angr, pick a function, and run the model."""

    with st.spinner("Analysing binary with angr (CFG) …"):
        proj, cfg = load_project(binary_path)

    if proj is None or cfg is None:
        st.error("angr could not load the binary.")
        return

    st.success(f"Binary loaded: **{display_name}**")

    # ── Function picker ──────────────────────────────────────────────────
    # Known CRT / linker functions that should never appear in the picker
    _CRT_JUNK = {
        "_init", "_fini", "_start", "frame_dummy",
        "deregister_tm_clones", "register_tm_clones",
        "__do_global_dtors_aux", "__libc_csu_init", "__libc_csu_fini",
        "__libc_start_main", "__gmon_start__",
        "UnresolvableJumpTarget", "UnresolvableCallTarget",
    }

    all_funcs = sorted(cfg.functions.values(), key=lambda f: f.addr)
    user_funcs = [
        f for f in all_funcs
        if is_relevant_user_like_function(f)
        and not f.is_plt
        and f.name not in _CRT_JUNK
        and not f.name.startswith("sub_")
    ]
    if not user_funcs:
        user_funcs = [
            f for f in all_funcs
            if not f.is_plt
            and f.name not in _CRT_JUNK
            and not f.name.startswith("sub_")
            and not f.name.startswith("_")
        ]

    func_names = [f.name for f in user_funcs]
    if not func_names:
        st.warning("No user functions found.")
        return

    default_idx = func_names.index("main") if "main" in func_names else 0
    selected_name = st.selectbox("Select function", func_names,
                                 index=default_idx,
                                 key=f"func_{display_name}")
    selected_func = next(f for f in user_funcs if f.name == selected_name)

    if show_objdump:
        col_asm, col_objdump, col_cfg = st.columns(3)
    else:
        col_asm, col_cfg = st.columns(2)

    with col_asm:
        st.subheader("Disassembly (angr)")
        asm_text = get_function_assembly(selected_func)
        st.code(asm_text or "(empty)", language="nasm")

    if show_objdump:
        with col_objdump:
            st.subheader("Disassembly (objdump)")
            objdump_text = _get_objdump_for_function(binary_path, selected_name)
            st.code(objdump_text or "(not found)", language="nasm")

    with col_cfg:
        st.subheader("Function Overview")
        st.markdown(f"- **Name:** `{selected_func.name}`")
        st.markdown(f"- **Address:** `{hex(selected_func.addr)}`")
        st.markdown(f"- **Basic Blocks:** {len(list(selected_func.blocks))}")

        callgraph = cfg.functions.callgraph
        _HIDE = _CRT_JUNK | JUNK_FUNCTIONS
        callees = [
            cfg.functions.get_by_addr(a).name
            for a in callgraph.successors(selected_func.addr)
            if cfg.functions.get_by_addr(a) is not None
            and cfg.functions.get_by_addr(a).name not in _HIDE
            and not cfg.functions.get_by_addr(a).is_plt
        ]
        callers = [
            cfg.functions.get_by_addr(a).name
            for a in callgraph.predecessors(selected_func.addr)
            if cfg.functions.get_by_addr(a) is not None
            and cfg.functions.get_by_addr(a).name not in _HIDE
            and not cfg.functions.get_by_addr(a).is_plt
        ]
        if callees:
            st.markdown("**Callees:** " + ", ".join(f"`{c}`" for c in callees))
        if callers:
            st.markdown("**Callers:** " + ", ".join(f"`{c}`" for c in callers))

    # ── Decompile button
    # Session state key for persisting results across reruns
    result_key = f"result_{display_name}"

    stored = st.session_state.get(result_key)
    if stored and stored.get("func") != selected_name:
        del st.session_state[result_key]
        stored = None

    if st.button("Decompile with LongT5", type="primary",
                 key=f"decompile_{display_name}"):
        tokenizer, model, device = load_model()

        with st.spinner("Pipeline: generating input …"):
            sample = build_sample(
                binary_path,
                selected_name,
                mode="test",
                UseContext="true" if context_mode == "Heuristic BFS Context" else "false",
                strip_operand_sizes=norm_strip_sizes,
                abstract_strings=norm_abstract_strings,
            )

        if sample is None:
            st.error("Pipeline could not generate an input.")
            return

        with st.spinner("LongT5: generating C code …"):
            inputs = tokenizer(
                sample["model_input"],
                return_tensors="pt",
                max_length=MAX_SOURCE_LENGTH,
                truncation=True,
            ).to(device)

            gen_kwargs = dict(
                    max_new_tokens=MAX_NEW_TOKENS,
                    repetition_penalty=rep_penalty,
                    no_repeat_ngram_size=5,
                )
            if temperature > 0:
                gen_kwargs.update(do_sample=True, temperature=temperature, top_p=0.95)
            else:
                gen_kwargs.update(do_sample=False)

            with torch.no_grad():
                outputs = model.generate(**inputs, **gen_kwargs)

            pred = tokenizer.decode(outputs[0], skip_special_tokens=True)
            c_code = reconstruct_literals(pred, sample.get("constant_pool"))

        # Persist result in session state so it survives reruns
        st.session_state[result_key] = {
            "func": selected_name,
            "c_code": c_code,
            "model_input": sample["model_input"],
            "original_source": original_source,
        }

    # Show persisted result (survives selectbox changes etc.)
    stored = st.session_state.get(result_key)
    if stored and stored["func"] == selected_name:
        with st.expander("Show model input"):
            st.text(stored["model_input"][:4000])

        st.subheader("Generated C Code")
        st.code(stored["c_code"], language="c")

        orig = stored.get("original_source")
        if orig:
            func_snippet = extract_function_from_source(orig, selected_name)
            st.subheader("Original C Code")
            st.code(func_snippet or orig, language="c")

        st.download_button(
            "Download C code",
            data=stored["c_code"],
            file_name=f"{selected_name}.c",
            mime="text/x-csrc",
            key=f"dl_{display_name}_{selected_name}",
        )

tab_upload, tab_github = st.tabs(["Upload Binary", "Scrape GitHub Repo"])

# ── Tab 1: Upload ────────────────────────────────────────────────────────────
with tab_upload:
    uploaded_file = st.file_uploader(
        "Upload ELF-Binary", type=["bin", "exe", "o", "elf", "out"]
    )

    original_src = st.text_area(
        "Paste original C source (optional — enables comparison)",
        height=150,
        key="upload_original_source",
    )

    if uploaded_file is not None:
        # Re-use the same temp path across reruns so angr's cache hits
        cache_id = f"upload_{uploaded_file.name}_{uploaded_file.size}"
        if st.session_state.get("upload_cache_id") != cache_id:
            suffix = os.path.splitext(uploaded_file.name)[1] or ""
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            tmp.write(uploaded_file.read())
            tmp.flush()
            tmp.close()
            st.session_state["upload_cache_id"] = cache_id
            st.session_state["upload_tmp_path"] = tmp.name

        analyse_and_decompile(
            st.session_state["upload_tmp_path"], uploaded_file.name,
            original_source=original_src if original_src.strip() else None,
        )

# ── Tab 2: GitHub Scrape ─────────────────────────────────────────────────────
with tab_github:
    st.markdown(
        "Enter a **GitHub-Repo-URL** (e.g. `https://github.com/user/repo`). "
        "The demo downloads all `.c` files, compiles them with `gcc`, "
        "and runs the Neural Decompiler on them."
    )

    col_url, col_token = st.columns([3, 1])
    with col_url:
        repo_url = st.text_input("GitHub Repo URL",
                                 placeholder="https://github.com/owner/repo")
    with col_token:
        gh_token = st.text_input("GitHub Token (optional)", type="password",
                                 help="Increases the API rate limit")

    if repo_url:
        parsed = parse_github_url(repo_url)
        if parsed is None:
            st.error("Invalid GitHub URL. Format: `https://github.com/owner/repo`")
            st.stop()

        owner, repo = parsed
        st.info(f"Repository: **{owner}/{repo}**")

        c_files = fetch_c_files_from_repo(owner, repo, gh_token or None)

        if not c_files:
            st.warning("No `.c` files found in repository.")
            st.stop()

        st.success(f"**{len(c_files)}** C files found.")

        file_names = [f["path"] for f in c_files]
        selected_c = st.selectbox("Select C file", file_names)
        selected_meta = next(f for f in c_files if f["path"] == selected_c)

        # Download & show source
        headers = {"Accept": "application/vnd.github.v3+json"}
        if gh_token:
            headers["Authorization"] = f"token {gh_token}"
        src_resp = requests.get(selected_meta["download_url"],
                                headers=headers, timeout=30)
        if src_resp.status_code != 200:
            st.error("Could not download file.")
            st.stop()

        c_source = src_resp.text

        with st.expander("Show original C source code", expanded=True):
            st.code(c_source, language="c")

        # Compile — persist binary path in session_state
        # Clear compiled state if user switched to a different C file
        if st.session_state.get("gh_selected_file") != selected_c:
            st.session_state.pop("gh_bin_path", None)
            st.session_state.pop("gh_display", None)
            st.session_state.pop("gh_compile_error", None)
            st.session_state["gh_selected_file"] = selected_c

        if st.button("Compile", type="primary"):
            work_dir = tempfile.mkdtemp(prefix="nd_github_")
            fname = os.path.basename(selected_c)

            with st.spinner(f"Compiling `{fname}` with gcc …"):
                bin_path = compile_c_to_binary(c_source, fname, work_dir)

            if bin_path is None:
                st.session_state["gh_compile_error"] = fname
                st.session_state.pop("gh_bin_path", None)
            else:
                st.session_state["gh_bin_path"] = bin_path
                st.session_state["gh_display"] = f"{owner}/{repo}/{selected_c}"
                st.session_state.pop("gh_compile_error", None)

        # Show compile error if stored
        if st.session_state.get("gh_compile_error"):
            fname = st.session_state["gh_compile_error"]
            st.error(
                f"`{fname}` could not be compiled. "
                "There may be missing dependencies or syntax errors."
            )

        # Show analysis if binary was compiled successfully
        if st.session_state.get("gh_bin_path"):
            bin_path = st.session_state["gh_bin_path"]
            gh_display = st.session_state["gh_display"]
            st.success(f"Compiled: `{os.path.basename(bin_path)}`")
            analyse_and_decompile(bin_path, gh_display,
                                  original_source=c_source)
