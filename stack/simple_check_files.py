#!/usr/bin/env python3

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is used to check that all installation files (except ignored and exceptions) have the expected permissions, owner, group ...
# It is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import argparse
import os
import grp
import pwd
import stat
import sys

_filemode_table = (
    ((stat.S_IFLNK, "l"),
     (stat.S_IFREG, "-"),
     (stat.S_IFBLK, "b"),
     (stat.S_IFDIR, "d"),
     (stat.S_IFCHR, "c"),
     (stat.S_IFIFO, "p")),

    ((stat.S_IRUSR, "r"),),
    ((stat.S_IWUSR, "w"),),
    ((stat.S_IXUSR | stat.S_ISUID, "s"),
     (stat.S_ISUID, "S"),
     (stat.S_IXUSR, "x")),

    ((stat.S_IRGRP, "r"),),
    ((stat.S_IWGRP, "w"),),
    ((stat.S_IXGRP | stat.S_ISGID, "s"),
     (stat.S_ISGID, "S"),
     (stat.S_IXGRP, "x")),

    ((stat.S_IROTH, "r"),),
    ((stat.S_IWOTH, "w"),),
    ((stat.S_IXOTH | stat.S_ISVTX, "t"),
     (stat.S_ISVTX, "T"),
     (stat.S_IXOTH, "x"))
)

def read_simple_check_file(file_to_check):
    expected_items = {}
    output_dict = {}

    json_data_list = read_json_file(file_to_check)['data']

    for data_item in json_data_list:
        output_dict[data_item['name']] = data_item['description']

    for item in output_dict:
        new_item = dict(output_dict[item])
        expected_items[item] = new_item

    return expected_items

# ---------------------------------------------------------------------------------------------------------------

"""
    Read a json file and return a json object.

    Parameters:
        - filepath: json file path.

    Return:
        Json object with the filepath data
"""

def read_json_file(filepath):

    with open(filepath) as f_json:
        json_file = json.load(f_json)

    return json_file

# ---------------------------------------------------------------------------------------------------------------

"""
    Get the checkfile data from a file or directory.

    Parameters:
        - item: filepath or directory.

    Return:
        Dictonary with checkfile data.

    Example:
        '/var/ossec/active-response' -->
            {
                "group": "wazuh",
                "mode": "0750",
                "prot": "drwxr-x---",
                "type": "directory",
                "user": "root"
            }
"""

def get_data(item):

    stat_info = os.stat(item)

    user = pwd.getpwuid(stat_info.st_uid)[0]
    group = grp.getgrgid(stat_info.st_gid)[0]
    mode = oct(stat.S_IMODE(stat_info.st_mode))
    mode_str = str(mode).replace('o', '')
    if len(mode_str) > 4:
        mode = mode_str[-4:]
    else:
        mode = mode_str
    prot = filemode(stat_info.st_mode)

    if os.path.isdir(item):
        type = "directory"
    else:
        type = "file"

    return {'group': group, 'mode': mode, 'type': type, 'user': user, 'prot': prot}

# ---------------------------------------------------------------------------------------------------------------

"""
    Get a dictionary with all checkfile information from all files and directories located in a specific path

    Parameters:
        - ossec_path: Path where the installation is located.

    Return:
        Dictonary with all check files corresponding to the installed files. It has the following format:

        "/var/ossec/active-response":{
            "group": "wazuh",
            "mode": "0750",
            "prot": "drwxr-x---",
            "type": "directory",
            "user": "root"
        }, ...
"""

def get_current_items(directories_to_check):
    
    c_items = {}
    for dir_to_check in directories_to_check:
        if os.path.exists(dir_to_check):
            if os.path.isdir(dir_to_check):
                for (dirpath, dirnames, filenames) in os.walk(dir_to_check, followlinks=False):
                    c_items[dirpath] = get_data(dirpath)

                    for filename in filenames:
                        file_path = "{0}/{1}".format(dirpath, filename)
                        c_items[file_path] = get_data(file_path)

            if os.path.isfile(dir_to_check):
                c_items[dir_to_check] = get_data(dir_to_check)

    return c_items

# ---------------------------------------------------------------------------------------------------------------

"""
    Get a List of files and directories to compare with installation

    Parameters:
        - file_to_check: template files with currentitems tag

    Return:
        List of files and directories to compare with installation

"""

def get_current_data(file_to_check):
    output = []

    json_data_list = read_json_file(file_to_check)['currentitems']

    for data_item in json_data_list:
        output.append(data_item['name'])

    return output

# ---------------------------------------------------------------------------------------------------------------

"""
    Convert a file's mode to a string of the form '-rwxrwxrwx'.

    Parameters:
        - mode: st_mode field of a file or directory from os.stat_result (Example: 16893)
    Return:
        String of the permissions set '-rwxrwxrwx'

    Example:
        33204 --> -rw-rw-r--

"""

def filemode(mode):

    perm = []
    for table in _filemode_table:
        for bit, char in table:
            if mode & bit == bit:
                perm.append(char)
                break
        else:
            perm.append("-")
    return "".join(perm)

# ---------------------------------------------------------------------------------------------------------------


if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-t", "--template", type=str, default="simple_check_file.json", help="File template check")
    #arg_parser.add_argument("-t", "--template", type=str, help="List of template files to check, comma-separated")
    args = arg_parser.parse_args()

    try:
        print(str(args))
        print("Checking files...")

        #directories_to_check = args.directory.split(',')
        file_to_check = args.template
        different_names = []

        #if "," in file_to_check:
        #    file_to_check = args.template.split(',')

        if not os.path.isfile(file_to_check):
            raise Exception(file_to_check + " not found")
        
        #Get current data to compare
        directories_to_check = get_current_data(file_to_check)

        print("Checking directories and files:")
        print(directories_to_check)

        #Get data to compare
        expected_items = read_simple_check_file(file_to_check)
        current_items = get_current_items(directories_to_check)

        #Get key name to compare
        expected_names = expected_items.keys()
        current_names = current_items.keys()

        # Missing files/directories
        missing_names = set(expected_names) - set(current_names)

        # Extra files/directories
        extra_names = set(current_names) - set(expected_names)

        # Different files/directories
        different_items = {}
        for item in expected_items:
            if item not in missing_names and expected_items[item] != current_items[item]:
                different_names.append(item)
                different_items[item] = expected_items[item]

        # Output
        different_names_output = ""
        for name in sorted(different_names):
            what = "Wrong: "
            if different_items[name]['user'] != current_items[name]['user']:
                what += " user"
            if different_items[name]['group'] != current_items[name]['group']:
                what += " group"
            if different_items[name]['mode'] != current_items[name]['mode']:
                what += " mode"

            different_names_output += "{0} [{1}]\n".format(name, what)
            different_names_output += "\tExpected: {0} {1}  {2}  # {3}\n".format(different_items[name]['user'], different_items[name]['group'], different_items[name]['mode'], different_items[name]['prot'])
            different_names_output += "\tFound   : {0} {1}  {2}  # {3}\n\n".format(current_items[name]['user'], current_items[name]['group'], current_items[name]['mode'], current_items[name]['prot'])

        extra_names_output = ""
        for name in sorted(extra_names):
            item_extra = get_data(name)
            extra_names_output += "{0}  [{1} {2} {3} {4}]\n".format(name, item_extra['user'], item_extra['group'], item_extra['mode'], item_extra['prot'])

        if missing_names:
            print("\nMissing (They are present in the check-files but they are not installed):")
            print('\n'.join(sorted(missing_names)))

        if extra_names:
            print("\nExtra (Not present in the chek-files but they are installed):")
            print(extra_names_output)

        if different_names:
            print("\nDifferent:")
            print(different_names_output)

        if missing_names or extra_names or different_names:
            print("\nPlease, review your files.")
            sys.exit(1)
        else:
            print("\nCongrats!.")

    except Exception as e:
        print("Error: {0}".format(str(e)))
        raise
        sys.exit(1)
