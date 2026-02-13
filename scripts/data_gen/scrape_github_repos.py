"""
Scrapes C source files from GitHub repository and validates compilability.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import requests
import subprocess

# --- KONFIGURATION ---
GITHUB_TOKEN = 'TOKEN'  
TARGET_OWNER = 'OWNER'         
TARGET_REPO = 'REPO'            
OUTPUT_DIR = 'C_COMPILE'
# ---------------------

BASE_URL = 'https://api.github.com'

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def is_c_file_compilable(file_path):
    """
    Checks if C file can be compiled without errors.
    Args:
        :param file_path: Path to C source file.
        :return: True if compilation succeeds as boolean.
    """
    compile_cmd = f'gcc -o /dev/null "{file_path}"' 
    try:
        compile_result = subprocess.run(compile_cmd, shell=True, capture_output=True)
        return compile_result.returncode == 0
    except Exception as e:
        print(f"Fehler beim Kompilieren: {e}")
        return False

def scrape_specific_repo():
    """
    Downloads and validates C files from target GitHub repository.
    Args:
        :return: None. Saves compilable files to OUTPUT_DIR.
    """
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }

    print(f'Checking repository: {TARGET_OWNER}/{TARGET_REPO} ...')

    contents_url = f'{BASE_URL}/repos/{TARGET_OWNER}/{TARGET_REPO}/contents'
    
    response = requests.get(contents_url, headers=headers)

    if response.status_code == 200:
        contents = response.json()
        
        c_files = [file for file in contents if file['name'].endswith('.c')]

        if c_files:
            print(f'{len(c_files)} C files found.')
            
            for index, file_data in enumerate(c_files):
                file_name = file_data['name']
                download_url = file_data['download_url']
                
                save_path = os.path.join(OUTPUT_DIR, file_name)
                
                print(f'Downloading: {file_name} ...')
                
                file_response = requests.get(download_url, headers=headers)
                
                if file_response.status_code == 200:
                    with open(save_path, 'wb') as f:
                        f.write(file_response.content)
                    
                    if is_c_file_compilable(save_path):
                        print(f'{file_name} is compilable. Keeping.')
                    else:
                        print(f'{file_name} is NOT compilable. Deleting.')
                        os.remove(save_path)
                else:
                    print(f'Error downloading {file_name}')
        else:
            print('No .c files found in main directory.')
    else:
        print(f'Error accessing repository. Status Code: {response.status_code}')
        print(f'Response: {response.text}')

if __name__ == '__main__':
    if subprocess.call("which gcc", shell=True, stdout=subprocess.DEVNULL) != 0:
        print("ERROR: 'gcc' is not installed or not found in PATH.")
    else:
        scrape_specific_repo()