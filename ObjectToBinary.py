'''
WARNING!: WITH THIS SCRIPT WE GENERATE ARBITRARY EXECUTEABLE PROGRAMS. DO NOT EXECUTE ANY PROGRAM. IT MIGHT BE MALICIOUS.
BE AWARE THAT EXECUTING THE PRE-SCRIPT ScraperSHO.py IS ALSO NOT SAFE TO EXECUTE.
SETTING UP A VIRTUAL ENVIRONTMENT FOR SECURELY EXECUTING THESE SCRIPTS IS AT YOUR RESPONSIBILITY.

Developed by Burhan Akin Yilmaz, Master of Data and CS Student, Universität Heidelberg.

This script is intended to be executed after ScraperSHO.py (SHO stands for "source and header to object").
The script figures out the dependencies between object files within a directory, and links them to an executeable file.
First, we figure out which files have the main (function) entry point. We then deduce by the symbols, which other object files are necessary for resolving undefined references, and recursively find other new objectfiles that are relevant.
Then, we run the compiler on the main object file, including the other relevant object files.

There is two possibilities to implement this idea.
1.) The easy method: We just find the main file, and throw ANY object file to the compiler within the directory that has no main entry point.

Problem: The problem with this approach is, that GCC does not remove dead code by default.
That means, if we have a self-enclosed main.c file, which we compile to an executeable, we could also throw additional object files to the compiler that are not relevant.
Inspecting the objdump reveals that all unused data and functions are still involved in the executable. Imagine the scenario we have one repository with two self-enclosed source files
(both contain main, and are compileable by their own), and many other source/header files.
Now due to our approach, we would have duplicates in our training data.

Solution: DEADCODESTRIP := -Wl,-static -fvtable-gc -fdata-sections -ffunction-sections -Wl,--gc-sections
This does not eliminate dead code within functions.
"Note that objects compiled without the -ffunction-sections and -fdata-sections options can still be linked with the executable.
 However, no dead code elimination will be performed on those objects (they will be linked as is)." - https://gcc.gnu.org/onlinedocs/gnat_ugn/Compilation-options.html

Problem: We eventually lose valueable training data, plus the compilation is slowed down.

Since we believe that "every drop" of training data is important, we will stick to the more complicated approach, see below.

2.) The hard method: We run over every object file in the directory and execute the following steps:
    0. Initialize an array dependentOn, which will store all relevant object files. Goto 1.
    1. We scan recursively trough the repository, and find the next potential relevant object file. If no more object files exist we temrinate and return dependentOn, otherwise goto 2.
    2. Check whether the given object file is different from the main file. If not goto 1., otherwise goto 3.
    3. Extract the defined symbols and check whether there is an intersection with the undefined symbols. If so append the file to dependentOn. Goto 4.
    4. We now have to recursively check all dependencies towards this new object file. Goto 1.

    Note, some symbols are from standard library/ other system libraries, we definitely will end with O(n^2) complexity checking one file against all others.

USAGE:
1. Set repo_directory to your directory which contains all repos which in turn contain object files in arbitrary subdirectories.
   Note: The script assumes object files within one directory are related, no matter how nested apart the paths are from each other.
2. python3 ObjectToBinary.py

Output: Object files linked to executeables at the path COMPILED/<REPOSITORY>/program_<index>, where <index> is the i-th program that was able to be generated within one Github <REPOSITORY>.

Performance:
CPU i7-9750H
The ScraperSHO.py can download and compile about 51 object files per minute. That would be about half million of object files in one week.
The ObjectToTrain.py is not parallelized yet, but manages to link 51 object files to executables in about 6 seconds, 734400 object files processed in one day.


TIP:
- Read the tips from the docstring in ScraperSHO.py
- One can parallelize both scripts. One scrapes data and generates object files, one immediately links the object files.
  Be careful to not bottleneck any process. The important part is to not stress the ScraperSHO.py with CPU intensive tasks.
  If there is the possibility to download source files, then download source files, don't be interrupted by other processes.

NOTE:
- If you want to compile with debug informaiton, make sure the ScraperSHO.py generates the object files accordingly with the same compiler options/setting.
Fun Fact: Developed within the noise of relatives, 4 children, sisters, brother-in-laws, ... Not sure how I was able to focus.
'''

import sys

sys.setrecursionlimit(2000)

import subprocess
import os
import time
import json
import re
from argparse import RawTextHelpFormatter # For formatting help text
import argparse

from multiprocessing import Pool # https://docs.python.org/3/library/multiprocessing.html
import multiprocessing



def getNM(file):
    nm_command = f'nm {file}'
    symbols = subprocess.getoutput(nm_command)
    symbol_lines_array = symbols.split("\n")
    symbols_row_column = []
    for line in symbol_lines_array:
        symbols_row_column+=[line.split()]
    return symbols_row_column
def getSymbols(symbols_row_column,symbol):
    '''
    Input: nm file output as 2d array
    Output: Array of undefined symbols
    Complexity: O(n)
    '''
    symbols = []
    for line in symbols_row_column:
        if line and len(line) >= 2 and line[-2]==symbol: # e.g. symbol = 'U' for undefined
            symbols.append(line[-1])
    return symbols

def isMain(symbols_row_column):
    '''
    Input: nm file output as 2d array.
    Output: True or False
    Checks, if a file has a main function or not.
    Complexity: O(n)
    '''
    for line in symbols_row_column:
        if line and line[-1]=='main':
            return True
    return False

def iterate_directories(directory,dependency):
    with os.scandir(directory) as directories:
        for element in directories:
            if element.is_dir():
                dependency = iterate_directories(element.path, dependency) # We give also give dependency list, the recursive call will append to it
            elif element.is_file() and element.name.endswith('.o'):
                object_file_path = element.path
                #print(object_file_path)
                symbols_r_c = getNM(object_file_path)
                dependency[object_file_path] = {
                    'isMain':isMain(symbols_r_c),
                    'undefined_U_Symbols': getSymbols(symbols_r_c, 'U'),
                    'defined_T_Symbols': getSymbols(symbols_r_c,'T'),
                    'dependentOn': None # We feed this information,  after every object files symbols is present
                }
    return dependency


def recursive_dependency_scan(current_object_path, undefined_U_Symbols, dependency, dependentOn=None):
    '''
    Input: (Object file with main entry point, Undefined U symbols extracted from nm)
    Output: Array of object files that are related (i.e. object files that resolve undefined symbols for the main target file).
    Algorithm idea:
    0. Initialize an (empty) array dependentOn, which will store all relevant object files. Goto 1.
    1. We scan recursively trough the repository, and find the next potential relevant object file. If no more object files exist we temrinate and return dependentOn, otherwise goto 2.
    2. Check whether the given object file is different from the main file. If not goto 1., otherwise goto 3.
    3. Extract the defined symbols and check whether there is an intersection with the undefined symbols. If so append the file to dependentOn. Goto 4.
    4. We now have to recursively check all dependencies towards this new object file. Goto 1.
    '''
    # Problem:
    if not undefined_U_Symbols: # Early return if there are no undefined symbols.
        return list(set())
    if dependentOn is None:
        dependentOn = [] # Set to store relevant object files for our target main file e.g. key_main = '../main.o'
    for path, value in dependency.items(): # key is the object file path, value is the dependency object with the information isMain, undefined symbols, ...
        if path != current_object_path and path not in dependentOn: # To avoid loops, we check if path is not in the already traversed dependentOn.
            for symbol in value['defined_T_Symbols']:
                if "main" == symbol: # A object file with main entry point cannot depend on another file with main function.
                    break
                if symbol in undefined_U_Symbols:
                    dependentOn.append(path)
                    dependentOn.extend(recursive_dependency_scan(path, value['undefined_U_Symbols'], dependency, dependentOn))
                    break
    return list(set(dependentOn)) # Set of all relevant object files


from multiprocessing import Pool, Value

successfulLinkages = Value('i', 0) 
def linkObjects(compile_commands,entry, error_log_file='link_errors.txt'):
    '''
    Input: Array of compiler commands to be executed
    Output: Stores the final executeable files immediately at the repositories directory (i.e. at COMPILED/REPOSITORY1/program1)
    '''
    for command in compile_commands:
        compile_result = subprocess.run(command, shell=True, capture_output=True)

        if compile_result.returncode != 0:
            error_message = compile_result.stderr.decode('utf-8', errors='ignore')
            #with open(error_log_file, 'a',errors='ignore') as error_file:
            #    ...
            #    error_file.write(f"{compile_commands}\n{error_message}\n") You can log errors and inspect why the compilation did not happen
        elif compile_result.returncode == 0:
            print(f'{entry}: Successfully generated one binary file')
            with successfulLinkages.get_lock():  # Ensure atomicity
                successfulLinkages.value += 1


def update_c_file(file_path, program_index):
    '''
    We append to each source file a comment of the form //program0, program1, ... the moment we know for which target program it will be compiled to.
    Note: One source file can be compiled to multiple programs within one repository.
    Input: (File path to source.c file, target program index)
    Output: Updates source.c file by appending //program0, program1, ... as last line
    '''
    next_program = "executable" + program_index
    # Read file
    with open(file_path, 'r',errors='ignore') as file:
        lines = file.readlines()
    if lines and lines[-1].startswith("//executable"): #
        if next_program not in lines[-1]:
            lines[-1] = lines[-1].strip()+", "+next_program # strip is relevant to remove \n new line. Note: When we append, we need to explicitly mark a newline. Is strip really needed?
    else:
        # Note: 'lastline','newline' will be written to same line without linebreak despite lines.append
        lines.append("\n//"+next_program)
    # Write the modified content back to the file
    with open(file_path, 'w',errors='ignore') as file:
        file.writelines(lines)

def initiateObjectToBinary(args, directory_path): # directory_path is a repo path in COMPILED (the repo contains the object files).
    dest_path = args.dest_path # COMPILE
    source_repo_directory = args.source_path # C_COMPILE

    # entry is one repository. This function is getting called many times (all immediate directories will be traversed).
    if os.path.isdir(directory_path):
        print(directory_path)
        dependency = {}  # Variable to store dependencies between objectfiles per repository  .

        '''
        Dependency Dictionary Format:
        {
            '../main.o': {
                isMain: True,
                defined_T_Symbols: {},
                undefined_U_Symbols: {},
                dependentOn: {'rectangle.o', '../square.o', ...}
            },
            ...
        }
        '''

        dependency = iterate_directories(directory_path, dependency) # Here we traverse RECURSIVELY the DIRECTORIES!
        compile_commands = [] # Array of "gcc -o program main.o ..." commands, we might have multiple main-function files.


        for key, value in dependency.items(): # Iterate over all object files dependency dictionary
            if value['isMain'] == True:
                # We now iterate over every object file, and remove from the undefined symbol list every entry, that the new object file covers on its defined symbol list.
                # The moment the undefined list is empty we can compile to an executeable, ohterwise when all files have been traversed and we found nothing we terminate.
                relevant_object_files = recursive_dependency_scan(key, value['undefined_U_Symbols'], dependency) # Last argument is for loop-avoidance purposes
                #dependency[key]['dependentOn'] = relevant_object_files
                program_path = os.path.join(directory_path,'executable')
                compiler_setting = f'gcc -o {program_path}'
                program_index = str(len(compile_commands)) # Used to name the programs starting with program0
                # We generate the compile commands of the form: gcc -o program_index main.o other.o ..., where index is the i-th program.
                compile_commands.append(compiler_setting+str(len(compile_commands))+ ' ' + key + ' ' + ' '.join(relevant_object_files))
                # Here we append at the end of each source file .c the line "//<program_path1>, <program_path2>, ...".
                # Note: One source file can be used for multiple programs.
                # Don't forget the object file with the main entry function, which is not involved in the relevant_object_files
                for object_file_path in relevant_object_files+[key]: # key is the main object file we manually add.
                    path_normalized = object_file_path
                    path_elements = []
                    while True:
                        path_normalized, directory = os.path.split(path_normalized)

                        if directory != "":
                            path_elements.append(directory)
                        else:
                            if path_normalized != "":
                                path_elements.append(path_normalized)
                            break
                    #print("PATH ELEMENTS ", path_elements)
                    source_elements = []
                    source_path_normalized = os.path.join(dest_path,"pseudofile.c")
                    #print("source_path_norm", source_path_normalized)
                    while True:
                        source_path_normalized, directory = os.path.split(source_path_normalized)

                        if directory != "":
                            source_elements.append(directory)
                        else:
                            if source_path_normalized != "":
                                source_elements.append(source_path_normalized)
                            break
                    source_elements.reverse()  # Format is ["COMPILED","pseudofile"] or ["..", "dir", ...,"COMPILED","pseudofile"]
                    #print("SOURCE ELEMENTS ", source_elements)

                    path_elements.reverse()  # Format is ["COMPILED", "REPO1", ..., "file.o"]
                    path_elements[-1] = path_elements[-1].rsplit('.', 1)[0] + '.c' # Format is ["COMPILED, "REPO1", ..., "file.c"]
                    #print("source_repo ",source_repo_directory)
                    #print("path_elements ",source_repo_directory,*path_elements[len(source_elements)-1:])
                    respective_source_file_path = os.path.join(source_repo_directory,*path_elements[len(source_elements)-1:]) # Format is ["C_COMPILED, "REPO1", ..., "file.c"]
                    #print("respective_source ",respective_source_file_path)
                    update_c_file(respective_source_file_path, program_index) # Note, we update the C files with extra information of the expected exeutable name. The compilation might fail, and we still add the information.
        # Finally we link the objects and create an executeable.
        linkObjects(compile_commands, directory_path)

        # If you want, you can log the dependency here.
        '''
        dependency_path = os.path.join(directory_path,'dependency.json')
        with open(dependency_path, 'w') as file: # We only have object files, elf files, so no name conflict
            # Use json.dump to write the dictionary to the file
            json.dump(data, file, indent=4)
        '''
        # Reset the dependency for the next repository!
        dependency = {}


def list_immediate_folders(directory):
    immediate_folders = []

    # os.walk generates the file names in a directory tree, walking top-down.
    # In this case, we are only interested in the first level of directories.
    for root, dirs, files in os.walk(directory):
        # Iterate over the list of directory names in `dirs`
        for dir_name in dirs:
            # Join the root with each directory name to get the full path
            dir_path = os.path.join(root, dir_name)
            immediate_folders.append(dir_path)
        break  # We break after the first iteration to only get the first level of directories

    return immediate_folders

def parallel_process(args):
    with Pool(args.number_of_processes) as p:
        p.starmap(initiateObjectToBinary,
                  [(args, entry) for entry in list_immediate_folders(args.dest_path)])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=R'''
               ____  ___    ____ 
              / __ \|__ \  / __ )
             / / / /__/ / / __  /
            / /_/ // __/ / /_/ / 
            \____//____//_____/  

    '''
                                                 'Burhan Akin Yilmaz, Master of Data and CS Student, Universität Heidelberg.'
                                                 'This script is part of the training data collection process for the DecompilerAI project and is supposed to be executed after compilation phase $python3 SH20.py.\n'
                                                 'The current directory should have C_COMPILE and COMPILED as directory.\n'
                                                 'The script traverses COMPILED and uses a sophisticated approach to find relations between object files and links them to a binary file.\n'
                                                 'The binary file will be stored immediately below the repositories directory with a naming convention program0, program1, ... .\n'
                                                 '\nMinimal scommand:\n\n'
                                                 'python3 ObjectToBinary.py\n'
                                     , formatter_class=RawTextHelpFormatter)


    dest_path = 'COMPILED' # The path to the directory with the repository folders, which contain object files; For more complicated paths, use os.join!
    source_path = 'C_COMPILE'
    number_of_processes = 4
    default_compiler = 'gcc'  # Default compiler


    parser.add_argument('--dest-path', type=str, default=dest_path, help='Directory path that contains repositories with object files. (default: COMPILED)')
    parser.add_argument('--source-path', type=str, default=source_path,
                        help='Path to directory that contains all repositories with source and header files (default: C_COMPILE).')
    parser.add_argument('--compiler', type=str, choices=['gcc', 'clang'], default=default_compiler,
                        help='Choose the compiler: gcc or clang (default: GCC).')
    parser.add_argument('--number-of-processes', metavar='<Integer>', type=int, default=number_of_processes,
                        help='Number of processes to spawn in parallel for acceleration (default: 4)\n')
    # Parsing the arguments
    args = parser.parse_args()

    # Execution time calculated for initializing the parallel process object files to binaries.
    st = time.time()
    parallel_process(args)
    print("Created executable files: ",successfulLinkages.value)
    et = time.time()
    elapsed_time = et - st
    print('Execution time:', elapsed_time, 'seconds')