#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 26 11:45:27 2020

@author: vindus-thesis
"""
import sys, getopt, os, json

def main():
    #Basic input/output paths
    try:
        input_dir, output_dir = get_io_handles()
    except:
        print("Error: Check input and output paths.")
        
    #List of entire first level keys to remove.
    #Change if needed.
    rem_list = ["exported_activities", "browsable_activities", "icon_hidden", "icon_found", "android_api", "domains", "apkid", "urls", "firebase_urls", "emails", "strings", "files", "virus_total", "host_os" ,"base_url", "dwd_dir"]
    json_obj = ""
    
    #Need to create output directory if
    #it's not already there
    create_output_dir(output_dir)
    
    #Walking across every file in the input directory
    for root, dirs, files in os.walk(input_dir, topdown=True):
        for name in files:
            file_name = (os.path.join(root,name))
            with open(str(file_name), "r") as json_file_handle:
                json_obj = json.load(json_file_handle)
            #Using list comprehension and pop() to remove
            #keys found in rem_list[]
            [json_obj.pop(key) for key in rem_list]
            new_name = json_obj["file_name"]+'-'+json_obj['md5']+'-cleaned.json'
            #Write new json files to respective directory
            write_json_file(output_dir,new_name,json_obj)
    
    
def get_io_handles():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:", ['help',"ifolder=", "ofolder="])
    except getopt.GetoptError:
        print ('mobsf_api.py -i <input_folder> -o <output_folder>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('mobsf_api.py -i <input_folder> -o <output_folder>')
            sys.exit()
        elif opt in ("-i", "--ifolder"):
            input_dir = arg
        elif opt in ("-o", "--ofolder"):
            output_dir = arg
    print('\n\n')
    print(input_dir)
    print(output_dir)
    print('\n\n')
    return (input_dir, output_dir)



#May need to mess with the absolute path...
def create_output_dir(output_dir):
    if os.path.isdir(output_dir) == False:
        os.makedirs(output_dir)
    return

def write_json_file(output_dir,filename, data):
    with open(os.path.join(output_dir,filename), 'w') as chuck:
        json.dump(data,chuck)
    return

if __name__ == "__main__":
    main()
