'''
WARNING: Do not execute this script without an secured environment, or atleast, without privilege.

This script was developed by Akin Yilmaz, Master of Data and CS Student from University Heidelberg.

It traverses a directory C_COMPILE that contains subdirectories (repositories) with source and header files.
The script recursively finds all C files and compiles them with given arguments to object files.
The COMPILED directory maintains the same directory structure as C_COMPILE.

Usage:
    ($python3 SHScraper.py)
    $python3 SH2O.py
    ($python3 ObjectToBinary.py)

See $python3 SH2O.py -h for options

If a file <file.c> is compileable the respective source file will have a prefix line with the respective compiler command that caused the succesful compilation of <file>.c.
The script also generates a compiler_errors.txt, to log the error messages for failed compilations.
One could install via sudo apt-get install relevant frequently used external libraries, check External_Libraries.txt. This reduces the amount of failed compilations heavily.

Please use a virtual environment before executing this script. Compilers may contain exploits. Also compiler bombs can blow up your entire memory : ).
'''

from argparse import RawTextHelpFormatter # For formatting help text
import argparse
import shutil
import re
import os
import subprocess
import time
import shlex
from typing import List
from multiprocessing import Pool, Value # https://docs.python.org/3/library/multiprocessing.html
import multiprocessing


RED = "\033[31m"
GREEN = "\033[32m"
RESET = "\033[0m"

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_EXTRA_INCLUDE_DIRS = []
for _hint in ("lua", "python", "yajl", "pcap"):
    _candidate = os.path.join(_SCRIPT_DIR, "EXTRA_INCLUDES", _hint)
    if os.path.isdir(_candidate):
        _DEFAULT_EXTRA_INCLUDE_DIRS.append(_candidate)

_SYSTEM_INCLUDE_PREFIXES = {
    "linux",
    "sys",
    "net",
    "asm",
    "arpa",
    "bits",
    "machine",
    "gnu",
    "drm",
    "sound",
    "video",
    "scsi",
    "mtd",
    "usb",
    "media",
    "rdma",
}


def replace_include_directives(c_code):
    '''
    Input: C code
    Output: C code where all occurences of #include <...> is replaced by "...".
    Reason: With "..." we check first local directiories, and then system directories.
    Some repositories install e.g. via CMake (shared) libraries and the source codes use <...>. Compiler won't search local directories, even though we have the headers!
    '''
    # Regular expression to match #include <...> with arbitrarily many spaces after the include keyword.
    # #include<...> #include        <...> ...
    pattern = r'#include\s*<(.*?)>'

    def _replace(match):
        target = match.group(1).strip()
        if "/" in target:
            prefix = target.split("/", 1)[0].lower()
            if prefix in _SYSTEM_INCLUDE_PREFIXES:
                return match.group(0)
        return f'#include "{target}"'

    include_replaced_code = re.sub(pattern, _replace, c_code)

    return include_replaced_code

def get_arg_max():
    try:
        # Run the 'getconf ARG_MAX' command and capture its output
        result = subprocess.check_output(['getconf', 'ARG_MAX'], text=True)
        # Strip any extra whitespace and return the value as an integer
        return int(result.strip())
    except Exception as e:
        return str(e)

MAX_SHELL_SIZE = get_arg_max()


def _extract_embedded_compile_flags(c_file_path: str) -> List[str]:
    """
    Parse the leading //gcc ... line (if any) to reuse previously successful flags.
    """
    try:
        with open(c_file_path, "r", errors="ignore") as handle:
            for _ in range(5):
                line = handle.readline()
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                if not stripped.startswith("//"):
                    break
                candidate = stripped[2:].strip()
                if candidate.startswith(("gcc ", "clang ")):
                    return _filter_reusable_flags(candidate, c_file_path)
                break
    except OSError:
        pass
    return []


def _filter_reusable_flags(command_line: str, source_path: str) -> List[str]:
    """
    Extract only the include/macro flags we want to reuse.
    """
    try:
        parts = shlex.split(command_line)
    except ValueError:
        return []

    reusable: List[str] = []
    i = 1  # skip compiler binary
    while i < len(parts):
        token = parts[i]

        if token == "-o":
            i += 2
            continue
        if token.startswith("-o"):
            i += 1
            continue
        if token.startswith("-O") or token.startswith("-g") or token in ("-c", "-S", "-E"):
            i += 1
            continue
        if token == source_path or token.startswith(source_path):
            i += 1
            continue

        if token in ("-I", "-isystem", "-D", "-include"):
            if i + 1 < len(parts):
                reusable.extend([token, parts[i + 1]])
                i += 2
                continue
            break

        if token.startswith(("-I", "-D", "-isystem", "-include", "-std=")):
            reusable.append(token)
            i += 1
            continue

        i += 1

    return reusable
# Function to check if a C file is compilable
def is_c_file_compilable(c_file_path, visited_include_folders,args, error_log_file='compile_errors.txt'):
    '''
    This function checks if a source.c is compilable using given compiler, and stores the object files in a directory COMPILED its structure is equal to repos on Github.
    If a source file is compiled in reponame_repoowner/master/src/source.c,
    we store the object file in COMPILED/reponame_repoowner/src/source.o.
    We make in addition sure, the compiler checks Include directory for missing headers, since we manually download Include directories from Github without any interaction with source files.
    We make sure the compilation time takes less than two minutes and consumes less than 100MB of storage, to avoid compiler bombs, and in general too much waiting time per repo.
    '''
    destinationPath = args.dest_path
    compiler = args.compiler
    optimization_level = args.optimization
    timeout = args.timeout
    max_file_size = args.max_file_size
    extra_include_dirs = args.extra_include_dir or []
    
    path_elements = []
    path_normalized = c_file_path

    while True:
        path_normalized, directory = os.path.split(path_normalized)

        if directory != "":
            path_elements.append(directory)
        else:
            if path_normalized != "":
                path_elements.append(path_normalized)
            break
    path_elements.reverse()  # Format is ["dir1", "dir2", ..., "header.h"]


    source_elements = []
    source_path_normalized = os.path.join(args.source_path,"pseudofile.c") # The below os.path.split always splits to directory+header, where header is a file. So we add a pseudo file.
    while True:
        source_path_normalized, directory = os.path.split(source_path_normalized)

        if directory != "":
            source_elements.append(directory)
        else:
            if source_path_normalized != "":
                source_elements.append(source_path_normalized)
            break
    source_elements.reverse()  # Format is ["..", "dir", ...,"COMPILE_C"]

    file_name = path_elements[-1]  # Get file name

    directory_elements = path_elements[
                         len(source_elements)-1:-1]  # Get the neccessary directory structure /directory1/directory2 but remove ->C_COMPILE<-/directory1/directory2
                         #Keep in mind that user can give relative paths of the form ../COMPILED/ so we need to pay attention where the directory1 index starts.

    # Now we can construct the destination directory which is a mirror except C_COMPILE -> COMPILED
    compile_destination_directory = os.path.join(destinationPath,*directory_elements) # C_COMPILE/dir1/.../dirn -> COMPILE/dir1/.../dirn
    os.makedirs(compile_destination_directory, exist_ok=True)
    # Final compile destination by turning filename.c to filename.o, so we will store gccs output at compile_destination_directory/filename.o
    compile_destination = os.path.join(compile_destination_directory,file_name.rsplit('.', 1)[0] + '.o')
    include_dir_candidates = visited_include_folders + extra_include_dirs
    seen_dirs = []
    for folder in include_dir_candidates:
        if not folder:
            continue
        if not os.path.isdir(folder):
            continue
        if folder not in seen_dirs:
            seen_dirs.append(folder)

    include_flags: List[str] = []
    for folder in seen_dirs:
        include_flags.extend(["-I", folder])

    embedded_flags = _extract_embedded_compile_flags(c_file_path)
    # before we compile, we save the original source
    try:
        with open(c_file_path, 'r', errors='ignore') as c_file:
            original_c_code = c_file.read()
    except OSError:
        original_c_code = None

    # We use temporary files for preprocessing and adjust all include headers of the form #include <...> to #include "...". The reason is explained in replace_include_directives() docstring.    
    temp_source_path = os.path.join(
        os.path.dirname(c_file_path),
        f"temp{os.getpid()}_{os.path.basename(c_file_path)}"
    )
    source_for_compile = c_file_path  # fallback if preprocessing crashes

    # We use a temporary file for preprocessing and then only modify that copy
    preproc_cmd = (
        f"gcc -fpreprocessed -dD -E -P {shlex.quote(c_file_path)} "
        f"-o {shlex.quote(temp_source_path)}"
    )
    preproc_result = subprocess.run(preproc_cmd, shell=True, capture_output=True)

    if preproc_result.returncode == 0 and os.path.exists(temp_source_path):
        # succesful preprocessing -> temp data 
        source_for_compile = temp_source_path

    # We rewrite the includes to only the compile source
    try:
        with open(source_for_compile, 'r', errors='ignore') as c_file:
            c_code_for_compile = c_file.read()
        c_code_for_compile = replace_include_directives(c_code_for_compile)
        with open(source_for_compile, 'w', errors='ignore') as c_file:
            c_file.write(c_code_for_compile)
    except OSError:
        # in any case of error
        source_for_compile = c_file_path

    # We prepare the compile process:

    #Uncomment if you want comments maintained! But then you need a new solution, since you can't have one lined programs anymore.
    #Maybe don't remove linebreak informations
    # compiler_preprocessor_rm_comments = subprocess.run(f"gcc -fpreprocessed -dD -E -P  {c_file_path} -o temp{os.getpid()}.c && mv temp{os.getpid()}.c {c_file_path}", shell=True, capture_output=True)

    # with open(c_file_path, 'r', errors='ignore') as c_file:
    #     c_code = c_file.read()
    # c_code = replace_include_directives(c_code)
    # with open(c_file_path, 'w', errors='ignore') as c_file:
    #     c_file.write(c_code)

    # Note: -I argument takes directory path without space. If we run gcc -c source.c with subdir "Include" we use -IInclude to pass Include directory

    compiler_bomb_restriction_prefix = f'ulimit -f {max_file_size} && timeout {timeout} '
    compiler_parts = [
        compiler,
        "-c",
        "-gdwarf",
        f"-O{optimization_level}",
        "-o",
        compile_destination,
        source_for_compile,
    ] + include_flags + embedded_flags
    compiler_options = ' '.join(shlex.quote(part) for part in compiler_parts)
    compile_cmd = compiler_bomb_restriction_prefix+compiler_options
    if len(compile_cmd) > MAX_SHELL_SIZE: # Windows max size shell is 8191
        return 0

    compile_result = subprocess.run(compile_cmd, shell=True, capture_output=True)

    # removing the temporary files (if it was created)
    if source_for_compile == temp_source_path and os.path.exists(temp_source_path):
        try:
            os.remove(temp_source_path)
        except OSError:
            pass

    if compile_result.returncode != 0:
        error_message = compile_result.stderr.decode('utf-8',errors='ignore')
        with open(error_log_file, 'a',errors='ignore') as error_file:
            error_file.write(f"{compile_cmd}\n{c_file_path}\n{error_message}\n")
    elif compile_result.returncode == 0:
        if original_c_code is not None:
            try: 
                # Here we prepend to the source code how the object file was compiled (all include directories), e.g. "gcc -c -o COMPILED/.../random.o C_COMPILE/.../random.c -IC_COMPILE/.../Includes"
                with open(c_file_path, 'w', errors='ignore') as c_file:
                    c_file.write(f'//{compiler_options}\n{original_c_code}')
            except OSError:
                pass
    return compile_result.returncode == 0

def is_within_directory(base_directory, target_path):
    # Get the absolute paths of the base directory and the target path
    base_directory = os.path.abspath(base_directory)
    target_path = os.path.abspath(target_path)

    # Check if the target path starts with the base directory
    return os.path.commonpath([base_directory, target_path]) == base_directory

def list_immediate_folders(directory, start_folder=None):
    immediate_folders = []

    start_collecting = start_folder is None # Boolean whether to start immediately or not depending if start_folder is set
    # os.walk generates the file names in a directory tree, walking top-down.
    # In this case, we are only interested in the first level of directories.
    for root, dirs, files in os.walk(directory):
        # Iterate over the list of directory names in `dirs`
        for dir_name in dirs:
            if not start_collecting and dir_name == start_folder:
                start_collecting = True
            # Join the root with each directory name to get the full path
            if start_collecting:
                dir_path = os.path.join(root, dir_name)
                immediate_folders.append(dir_path)
        break  # We break after the first iteration to only get the first level of directories

    return immediate_folders
def get_file_list(directory):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".c"):  # We only look for C files #CPP-Note
                file_list.append(file_path)
            # To not traverse twice due to performance reasons we do the following right here:
            # Before we compile, we adjust all include headers of the form #include <...> to #include "...". The reason is explained in replace_include_directives() docstring.
            if file.endswith(".h"):
                # Before we compile, we adjust all include headers of the form #include <...> to #include "...". The reason is explained in replace_include_directives() docstring.
                file_path = os.path.join(root, file)
                with open(file_path, 'r', errors='ignore') as h_file:
                    c_code = h_file.read()
                c_code = replace_include_directives(c_code)
                with open(file_path, 'w', errors='ignore') as h_file:
                    h_file.write(c_code)
    return file_list
def get_all_directories(directory):
    dir_list = []
    # os.walk generates the file names in a directory tree by walking either top-down or bottom-up.
    for root, dirs, files in os.walk(directory):
        for dir_name in dirs:
            # Construct the full path to the directory
            dir_path = os.path.join(root, dir_name)
            dir_list.append(dir_path)
    return dir_list



successfulCompilations = Value('i', 0) 
def compileRecursive(args, repository):
    global successfulCompilations
    visited_include_folders = get_all_directories(repository)
    for c_file_path in get_file_list(repository):
        if is_c_file_compilable(c_file_path, visited_include_folders, args):
            with successfulCompilations.get_lock():  # Ensure atomicity
                successfulCompilations.value += 1
            print(f'File {c_file_path} is {GREEN}COMPILEABLE.{RESET}')
        else:
            print(f'File {c_file_path} is {RED}NOT compileable{RESET}. Removing...')

def parallel_process(args):
    repositories = list_immediate_folders(args.source_path, args.start_folder)
    if not repositories:
        print("[INFO] No repositories found in COMPILED – nothing to link.")
        return

    cpu_count = multiprocessing.cpu_count() or 1

    requested = args.number_of_processes or cpu_count
    if requested <= 0:
        requested = cpu_count

    n_proc = max(1, min(requested, cpu_count, len(repositories)))

    print(f"[INFO] Found {len(repositories)} repositories with object files.")
    print(f"[INFO] Using {n_proc} worker processes (requested={requested}, cpus={cpu_count}).")

    with Pool(processes=n_proc) as p:
            p.starmap(compileRecursive,
                      [(args, entry) for entry in list_immediate_folders(args.source_path, args.start_folder)])



if __name__ == '__main__':
    
    # Setting up argparse to handle command-line arguments
    parser = argparse.ArgumentParser(description=R'''
               _____  __  __ ___   ____ 
              / ___/ / / / /|__ \ / __ \
              \__ \ / /_/ / __/ // / / /
             ___/ // __  / / __// /_/ / 
            /____//_/ /_/ /____/\____/  
                                      
'''
                                                 'This script is part of the training data collection process for the DecompilerAI project and is supposed to be executed after $python3 ScraperSH.py.\n'
                                                 'The current directory should have C_COMPILE as directory.\n'
                                                 'The script traverses C_COMPILE and compiles all source files with the header files to object files and stores them in COMPILED.\n'
                                                 'The COMPILED directory maintains the same directory structure as C_COMPILE\n'
                                                 '\nMinimal command:\n\n'
                                                 'python3 SH2O.py\n'
                                                 ,formatter_class=RawTextHelpFormatter)


    compilePath = "C_COMPILE" # Where our repositories with source and header files are
    destinationPath = "COMPILED" # Default destination where to store object files
    default_compiler = 'gcc'  # Default compiler
    default_optimization = '0' # -O0
    default_timeout = 60 # 60 standard
    default_max_file_size = 5242880 # 104857600 # 5242880 # 5 MB! Unit is in 512-byte blocks. ulimit -f 1 equals to max file size of 512 bytes. 1MB is 2^20 bytes, 10MB is 10*2^20 = 10485760 and divided by 512 byte blocks is 20480 blocks. https://www.ibm.com/docs/en/zos/2.4.0?topic=descriptions-ulimit-set-process-limits
    number_of_processes = 4
    start_folder = None
    # Adding the compile path argument
    parser.add_argument('--source-path', type=str, default=compilePath,metavar='<RELATIVE_PATH>', help='Directory path with all the repositories (default: C_COMPILE).')
    parser.add_argument('--dest-path', type=str, default=destinationPath,metavar='<STRING>',
                        help='Destination path where source directory with compilations will be mirrored to. (default: COMPILED).')
    parser.add_argument(
        '--extra-include-dir',
        action='append',
        default=list(_DEFAULT_EXTRA_INCLUDE_DIRS),
        metavar='<PATH>',
        help=(
            'Additional include directory to append to every compile command (repeatable). '
            f'Defaults: {_DEFAULT_EXTRA_INCLUDE_DIRS or "none"}.'
        ),
    )
    parser.add_argument('--compiler', type=str, choices=['gcc', 'clang'], default=default_compiler,
                        help='Choose the compiler: gcc or clang (default: GCC).')
    parser.add_argument('--optimization', type=str,  default=default_optimization,
                        help='Compiler Optimization Level that will be used with gcc -c -O<OPTIMIZATION> ... (default: 0).')
    parser.add_argument('--number-of-processes', metavar='<INTEGER>', type=int, default=number_of_processes,
                        help='Number of processes to spawn in parallel for acceleration (default: 4).\n')
    parser.add_argument('--timeout', metavar='<INTEGER>', type=int, default=default_timeout,
                        help='Maximal compilation time  in seconds per file (default: 60).\n')
    parser.add_argument('--max-file-size', metavar='<INTEGER>', type=int, default=default_max_file_size,
                        help='Maximal file size in bytes that one compilation phase can produce (in 512-byte blocks) (default: 20480 blocks ~ 10 MB)\n')
    parser.add_argument('--start-folder', metavar='<DIRECTORY_NAME>', type=str, default=start_folder,
                        help='The repository name from where the process should be continued. (Default: None)\n')

    '''
    Last Repo:
    File C_COMPILE/evolvIQ_iqserialization
    '''
    
    # Parsing the arguments
    args = parser.parse_args()

    # Execution time calculated for initializing the parallel process object files to binaries.
    st = time.time()

    parallel_process(args)
    print("Compiled object files: ",successfulCompilations.value)
    et = time.time()
    elapsed_time = et - st
    print('Execution time:', elapsed_time, 'seconds')
