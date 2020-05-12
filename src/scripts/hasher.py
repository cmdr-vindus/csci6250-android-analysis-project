#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Hasher: MD5 hashes an input directory and prints to screen
        Use: hasher.py -i /path/to/dir/
        Redirect output to a file if you want to save values.
"""


import sys, getopt, hashlib, os, shutil

def main():
    input_dir = ''
    output_file = ''

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:", ['help',"ifile=", "ofile"])
    except getopt.GetoptError:
        print ('hasher.py -i <input_dir> -o <output_file>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('hasher.py -i <input_dir> -o <output_file>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            input_dir = arg
        elif opt in ("-o", "--ofile"):
            output_file = arg

    
    #Moving the log.log and metadata.csv files out of the way for hashing
    #They can't be there for MobSF's mass_static_analysis.py either...
    #Just chucking them to the users home directory for now. Not clean...
    try:
        moveLogFile(input_dir)
    except:
        print("Failed to find/move Androzoo's log.log file.")
    try:
        moveMetaFile(input_dir)
    except:
        print("Failed to find/move Androzoo's metadata.csv file.")
    
    hash_collection = ''
    #Hashing section
    for root, dirs, files in os.walk(input_dir, topdown=True):
        for name in files:
            FileName = (os.path.join(root, name))
            
            #MobSF only accepts MD5 hashes for API calls
            hash_engine = hashlib.md5()
            with open(str(FileName), 'rb') as afile:
                buf = afile.read()
                hash_engine.update(buf)
                with open(str(output_file), 'w') as bfile:
                    hash_collection += hash_engine.hexdigest() + '\n'
                    bfile.write(hash_collection)
    return 

def moveLogFile(input_dir, name="log.log"):
    log_file_handle = ' '
    for root, dirs, files in os.walk(input_dir, topdown=True):
        if name in files:
            log_file_handle = os.path.join(root, name)
            shutil.move(log_file_handle, os.getenv('HOME'))
    return
            
def moveMetaFile(input_dir, name='metadata.csv'):
    meta_file_handle = ' '
    for root, dirs, files in os.walk(input_dir, topdown=True):
        if name in files:
            meta_file_handle = os.path.join(root, name)
            shutil.move(meta_file_handle, os.getenv('HOME'))
    return
    
if __name__ == "__main__":
    main()
