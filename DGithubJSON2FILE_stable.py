'''
This script was developed by Akin Yilmaz, Master of Data and CS Student from University Heidelberg.

GithubJSON2FILE.py is responsible for turning the JSON files created by the sequence
BigQuery Command -> Google Cloude Service Bucket -> Local Client via GCLOUD tool
to a folder with repositories which will contain .c and .h files.
The new folder C_COMPILE will therefore have thousands/millions of repositories,
that maintain the same directory structure as the original ones accesible by http://www.github.com.

HOW TO USE:
0. $pip install tqdm or $python3 -m pip install tqdm
1. Follow the instructions given in "BigQuery Github Datensatz Extraktion.pdf"
2. Make sure the folder UNZIPPED exists with the training files in JSON format.
3. $python3 GithubJSON2FILE.py

MISSING FEATURES:
    - Clean termination of multiple started processes

Possible exploits: We blindly store the files at the respective paths. It's better to force the files to be stored within the folder C_COMPILE.
Files should not be stored outside this folder by tricks like path = ../../../system32.
Therefore, we encourage you to execute this script on a virtual machine.
'''

import time
import os
import json
import argparse
import gzip
import shutil
import hashlib

from argparse import RawTextHelpFormatter
from multiprocessing import Pool  # https://docs.python.org/3/library/multiprocessing.html

def repo_hash(name):
    """Return a 14-char stable repo identifier."""
    return hashlib.sha1(name.encode("utf-8")).hexdigest()[:14]

def is_binary_string(s):
    """Heuristik: Skip binary content."""
    if isinstance(s, str):
        s = s.encode("utf-8", errors="ignore")
    return b'\x00' in s

def process_repo(repo, target_dir, max_path_len, json_source):
    try:
        # Safe fetch and hashed repo name to avoid collisions 
        repo_name = repo.get("repo_name", "unknown_repo").replace('/', '_')
        files = repo.get("file_array", [])

        repo_id = repo_hash(repo_name)
        repo_dir = os.path.join(target_dir, repo_id)
        repo_dir_abs = os.path.abspath(repo_dir)

        # Create the base directory for the repository
        os.makedirs(repo_dir_abs, exist_ok=True)

        # Counters for manifest
        written_count = 0
        binary_skips = 0
        unsafe_skips = 0
        write_errors = 0

        # Iterate through each file in the repository
        for file_info in files:
            file_path = file_info["file_path"]
            file_content = file_info["file_content"]
            
            if not file_path:
                print("[WARN] Missing file_path — skipping file")
                continue

            # C_COMPILE/<repo>/<file>(.c|.h)
            full_path = os.path.join(repo_dir_abs, file_path)

            # Normalize the path to remove any redundant slashes or dots
            normalized_path = os.path.abspath(os.path.normpath(full_path))

            if not normalized_path.startswith(repo_dir_abs + os.sep):
                unsafe_skips += 1
                print(f"[WARN] Unsafe path detected: {file_path}")
                continue

            # Checks first if max_path_len is set, and then checks if paths exceed maximal length
            if max_path_len and len(normalized_path) > max_path_len:
                print(f"[SKIP] Path too long: {normalized_path}")
                continue

            # Create any necessary directories for the file path
            os.makedirs(os.path.dirname(normalized_path), exist_ok=True)

            try:
                if is_binary_string(file_content):
                    binary_skips += 1
                    print(f"[SKIP] Binary file: {file_path}")
                    continue

                with open(normalized_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(file_content)
            except Exception as e:
                # This is the only tiny tweak: instead of exploding on weird paths, warn and move on
                print(f"[WARN] Could not write {normalized_path}: {e}")
                continue

        manifest = {
            "repo_name": repo_name,
            "repo_hash": repo_id,
            "json_source": json_source,
            "file_count_total": len(files),
            "file_count_written": written_count,
            "skipped_binary": binary_skips,
            "skipped_unsafe_paths": unsafe_skips,
            "write_errors": write_errors,
        }

        manifest_path = os.path.join(repo_dir_abs, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2)

    except Exception as e:
        # same idea as original: skip bad repo
        # original just continues silently; we add info but keep behaviour
        print(f"[WARN] Repository failed: {e}")

def initiateJSON2FILE(json_file, source_dir, target_dir):
    print(f'Target: {json_file} ...')
    max_path_len = 200 if os.name == 'nt' else None  # Max Windows path length

    json_file_path = os.path.join(source_dir, json_file)

    # data = [] TODO: we stream now instead of loading all at once
    with open(json_file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            try:
                repo = (json.loads(line))
            except Exception as e:
                # keep same semantics, but don't blow up
                print(f"[WARN] JSON decode error in {json_file}: {e}")
                continue

            # Iterate through each repository in the JSON data
            process_repo(repo, target_dir, max_path_len, json_source=json_file)

def process_single_json_file(args):
    json_files = os.listdir(args.source_path)
    with Pool(args.number_of_processes) as p:
        p.starmap(
            initiateJSON2FILE,
            [(json_file, args.source_path, args.target_path) for json_file in json_files]
        )
        #p.terminate()
        p.close() # lets current task clean up 
        p.join()


def unzip_file(gz_file, zipped_path, source_path):
    gz_file_path = os.path.join(zipped_path, gz_file)
    unzipped_file_name = os.path.splitext(gz_file)[0]
    unzipped_file_path = os.path.join(source_path, unzipped_file_name)

    # Unzip the file
    try:
        with gzip.open(gz_file_path, 'rb') as f_in:
            with open(unzipped_file_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"Unzipped {gz_file} to {unzipped_file_path}")
    except Exception as e:
        # <-- THIS is the main robustness change.
        # Deine kaputte Datei (EOFError) kommt hier rein.
        # Statt das ganze Programm abzuschießen, melden wir's nur.
        print(f"[WARN] Failed to unzip {gz_file}: {e}")


def process_single_gzip_file(args):
    os.makedirs(args.source_path, exist_ok=True)  # Ensure target directory exists
    zipped_files = os.listdir(args.zipped_path)

    with Pool(args.number_of_processes) as p:
        p.starmap(
            unzip_file,
            [(gz_file, args.zipped_path, args.source_path) for gz_file in zipped_files]
        )
        p.terminate()
        p.join()


if __name__ == '__main__':
    # Setting up argparse to handle command-line arguments
    # https://patorjk.com/software/taag/#p=display&h=1&f=Slant&t=SHScraper
    parser = argparse.ArgumentParser(description=r'''
    Developed by Burhan Akin Yilmaz
                ____   ______     __ ___    ______
               / __ \ / ____/    / /|__ \  / ____/
              / / / // / __ __  / / __/ / / /_    
             / /_/ // /_/ // /_/ / / __/ / __/    
            /_____/ \____/ \____/ /____//_/       
                      
''' +
    'This script is part of the training data collection process for the DecompilerAI project.\n'
    'It assumes the existence of a folder (default: UNZIPPED) which contains JSON files with information on github repositories.\n'
    'The format is given as follows:\n'
    '''[{
        "repo_name":"authorrepo",
        "file_array":
            [
                {
                    "file_path":"path/to/file1.c",
                    "file_content":"Content of the file1.c ..."
                }, ...
            ]
        }, 
        ...]
    ''' +
    '\nMinimal command:\n\n'
    'python3 GithubJSON2File.py\n'
    , formatter_class=RawTextHelpFormatter)

    #Defines directory, in which the GZIPPED files from BigQuery are
    zipped_dir = 'ZIPPED'

    # Defines directory which contains unzipped training data in JSON format
    source_dir = 'UNZIPPED'

    # Defines the base directory where the files will be stored
    target_dir = 'C_COMPILE'

    number_of_processes = 4

    parser.add_argument('--zipped-path', metavar='<path>', type=str, default=zipped_dir,
                        help='Defines a path where the gzipped jsonl files are stored (default: ZIPPED)\n')
    parser.add_argument('--source-path', metavar='<path>', type=str, default=source_dir,
                        help='Defines a path where the unzipped json files are stored at (default: UNZIPPED)\n')
    parser.add_argument('--target-path', metavar='<path>', type=str, default=target_dir,
                        help='Defines a path where the repositories should be stored at (default: C_COMPILE)\n')
    parser.add_argument('--number-of-processes', metavar='<Integer>', type=int, default=number_of_processes,
                        help='Number of processes to spawn in parallel for acceleration (default: 4)\n')

    # Parse args
    args = parser.parse_args()

    # Full pipeline: gzip -> json -> repo tree
    st = time.time()
    process_single_gzip_file(args)
    process_single_json_file(args)
    et = time.time()

    elapsed_time = et - st
    print('Execution time:', elapsed_time, 'seconds')
