#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
GPlay_Downloader: Testing GPlaycli intergration
                  Use: 
                
"""

import sys, getopt, os, json, subprocess, time

def main():
    #Basic input/output paths
    try:
        input_file, output_dir = get_io_handles()
    except:
        print("Error: Check input and output paths.")
        
    #Need to create output directory if
    #it's not already there
    create_output_dir(output_dir)
    
    #Gets a list of appId's i.e. com.facebook.katana
    appId_list = read_json_blob(input_file)
    
    download_apps(appId_list, output_dir)
    
    return

def get_io_handles():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:", ['help',"ifile=", "ofolder="])
    except getopt.GetoptError:
        print ('mobsf_api.py -i <input_file>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('mobsf_api.py -i <input_file> -o <output_folder>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            input_file = arg
        elif opt in ("-o", "--ofolder"):
            output_dir = arg
    print('\n\n')
    print(input_file)
    print(output_dir)
    print('\n\n')
    return (input_file, output_dir)


#May need to mess with the absolute path...
def create_output_dir(output_dir):
    if os.path.isdir(output_dir) == False:
        os.makedirs(output_dir)
    return

def read_json_blob(input_file):
    json_obj = 'apples'
   
    appId_list = []
    
    
    #POSSIBLY: Put os.walk junk back later
    with open(input_file, 'r') as chuck:
        json_obj = json.load(chuck)
    #print(json_obj)
    
    
    #Walking across every file in the input directory
    #for root, dirs, files in os.walk(input_file, topdown=True):
    #    for name in files:
    #        file_name = (os.path.join(root,name))
    #        with open(str(file_name), "r") as json_file_handle:
    #            json_obj = json.load(json_file_handle)
    #
    #       print(json_obj)
    
    #Read each appId from json_object
    for i in range(0,len(json_obj)):
        appId_list.append(json_obj[i]['appId'])
        
    return appId_list

def download_apps(appId_list, output_dir):
    #appId_len = len(appId_list)
    count = 1
    
    for app in appId_list:
        pass_args = []
        pass_args.append("gplaycli")
        pass_args.append("-d")
        pass_args.append(str(app))
        pass_args.append("-f")
        pass_args.append(str(output_dir))
        try:
            subprocess.check_call(pass_args)
            print(str(app) + " has been downloaded - total apps: " + str(count))
            count += 1
        except:
            print(str(app) + " failed to download - total apps: " + str(count))
        time.sleep(15)


if __name__ == "__main__":
    main()
