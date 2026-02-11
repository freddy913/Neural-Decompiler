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

from argparse import RawTextHelpFormatter

from multiprocessing import Pool # https://docs.python.org/3/library/multiprocessing.html


def initiateJSON2FILE(json_file,source_dir, target_dir):
    print(f'Target: {json_file} ...')
    max_path_len = 200 if os.name == 'nt' else None # Max Windows path length
    # Prepare iterating over JSON files from the source directory.

    json_file_path = os.path.join(source_dir, json_file)

    # Load the JSON data from the file

    data = []
    with open(json_file_path, 'r', encoding='utf-8',errors='ignore') as file:
        for line in file:
            try:
                data.append(json.loads(line))
            except Exception as e:
                print(e)
                print(f"{json_file_path}: Found an error to load JSON")
                continue
    # Max path length for Windows (reduce by a buffer), relevant for Windows only

    # Iterate through each repository in the JSON data
    for repo in data:
        try:
            repo_name = repo["repo_name"].replace('/', '_')
            files = repo["file_array"]
            # Create the base directory for the repository
            repo_dir = os.path.join(target_dir, repo_name)

            os.makedirs(repo_dir, exist_ok=True)
            # Iterate through each file in the repository
            for file_info in files:

                file_path = file_info["file_path"]
                file_content = file_info["file_content"]
                # Construct the path beginning from repository to the source or header file using os.path.join
                full_path = os.path.join(repo_dir, file_path) # C_COMPILE/<repo>/<file>(.c|.h)

                absolute_path_length = os.path.abspath(full_path) # usr/toge/C_COMPILE/<repo>/<file>(.c|.h)

                # Checks first if max_path_len is set, and then checks if paths exceed maximal length
                if max_path_len and len(absolute_path_length) > max_path_len:
                    continue

                # Create any necessary directories for the file path
                os.makedirs(os.path.dirname(full_path), exist_ok=True)


                # Normalize the path to remove any redundant slashes or dots
                normalized_path = os.path.normpath(full_path)

                with open(normalized_path, 'w', encoding='utf-8', errors='ignore') as file:
                    file.write(file_content)
        except Exception as e:
            #print(f'{json_file} caused the error {e}') # Usually this happens if repo has corrupt file paths or atleast unsupported file paths
            continue


def process_single_json_file(args):
    json_files = os.listdir(args.source_path)
    with Pool(args.number_of_processes) as p:
        p.starmap(initiateJSON2FILE, [(json_file, args.source_path, args.target_path) for json_file in json_files])
        p.terminate()
        p.join()

def unzip_file(gz_file, zipped_path, source_path):
    gz_file_path = os.path.join(zipped_path, gz_file)
    unzipped_file_name = os.path.splitext(gz_file)[0]
    unzipped_file_path = os.path.join(source_path, unzipped_file_name)

    # Unzip the file
    with gzip.open(gz_file_path, 'rb') as f_in:
        with open(unzipped_file_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    print(f"Unzipped {gz_file} to {unzipped_file_path}")

def process_single_gzip_file(args):
    os.makedirs(args.source_path, exist_ok=True)  # Ensure target directory exists
    zipped_files = os.listdir(args.zipped_path)
    
    with Pool(args.number_of_processes) as p:
        p.starmap(unzip_file, [(gz_file, args.zipped_path, args.source_path) for gz_file in zipped_files])
        p.terminate()
        p.join()


if __name__ == '__main__':
    # Setting up argparse to handle command-line arguments
    # https://patorjk.com/software/taag/#p=display&h=1&f=Slant&t=SHScraper Font Slant, Character Width: Fitted, Character Height: Default 3 tabs to right!
    # One empty line below, no empty line above and 3 tabs to right
    parser = argparse.ArgumentParser(description=R'''
    Developed by Burhan Akin Yilmaz
                ____   ______     __ ___    ______
               / __ \ / ____/    / /|__ \  / ____/
              / / / // / __ __  / / __/ / / /_    
             / /_/ // /_/ // /_/ / / __/ / __/    
            /_____/ \____/ \____/ /____//_/       
                      
'''

                                                 'This script is part of the training data collection process for the DecompilerAI project.\n'
                                                 'It assumes the existence of a folder (default: UNZIPPED) which contains JSON files with information on github repositories.\n'
                                                 'The format is given as follows:\n'
'''         [{
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
'''
                                                 '\nMinimal command:\n\n'
                                                 'python3 GithubJSON2File.py\n'
                                     , formatter_class=RawTextHelpFormatter)



    #Defines directory, in which the GZIPPED files from BigQuery are
    zipped_dir = 'ZIPPED'

    # Defines directory which contains unzipped training data in JSON format (previously GZIPPED from BigQuery to Bucket to Local Client).
    source_dir = 'UNZIPPED'


    # Defines the base directory where the files will be stored
    target_dir = 'C_COMPILE'
    # Adding the compile path argument
    number_of_processes = 4

    parser.add_argument('--zipped-path', metavar='<path>', type=str, default=zipped_dir,
                        help='Defines a path where the gzipped jsonl files are stored (default: ZIPPED)\n')
    parser.add_argument('--source-path', metavar='<path>', type=str, default=source_dir,
                        help='Defines a path where the unzipped json files are stored at (default: UNZIPPED)\n')
    parser.add_argument('--target-path', metavar='<path>', type=str, default=target_dir,
                        help='Defines a path where the repositories should be stored at (default: C_COMPILE)\n')
    parser.add_argument('--number-of-processes', metavar='<Integer>', type=int, default=number_of_processes,
                        help='Number of processes to spawn in parallel for acceleration (default: 4)\n')
    # Parsing the arguments
    args = parser.parse_args()


    # Execution time calculated for initializing the parallel process object files to binaries.
    st = time.time()
    process_single_gzip_file(args)
    process_single_json_file(args)

    et = time.time()
    elapsed_time = et - st
    print('Execution time:', elapsed_time, 'seconds')