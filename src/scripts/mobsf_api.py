#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Feb 12 16:12:58 2020

@author: vindus-thesis
"""
import json , os, sys, getopt, requests, time



#Global Variables (change later)
server = 'http://127.0.0.1:8000'
api_key = os.environ['MOBSF_API_KEY']
#input_file = ' '
#output_dir = ' '

def main():
    print(api_key + '\n')
    try:
        input_file, output_dir, error_dir = get_io_handles()
    except:
        print("Error: Check input, output, and error paths.")
        sys.exit(2)
        
    h_results = read_hashes(input_file)
    #print(h_results)
    
    create_output_dir(output_dir)
    create_output_dir(error_dir)
    
    for md5 in h_results:
        try:
            j_result = json_resp(md5)
            apk_name = j_result['file_name'] +'-'+j_result['md5']+'.json'
            write_json_file(output_dir, apk_name, j_result)
            time.sleep(5)
        except:
            print("Failed on apk hash: " + str(md5))
            write_failures(error_dir, md5)
            time.sleep(5)
        
    
    

def write_failures(error_dir, md5):
    with open(os.path.join(error_dir, 'failed-hashes'), 'a') as chuck:
        chuck.write(md5+'\n')
    return

def json_resp(data):
    """Generate JSON Report"""
    print("Generate JSON report")
    headers = {'Authorization': api_key}
    data = {"hash":data}
    response = requests.post(server + '/api/v1/report_json', data=data, headers=headers)
    
    ugly_json = json.loads(response.text)
    
    return ugly_json



def get_io_handles():

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:e:", ['help',"ifile=", "ofolder=","efolder="])
    except getopt.GetoptError:
        print ('mobsf_api.py -i <input_file> -o <output_dir> -e <error_dir>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('mobsf_api.py -i <input_file> -o <output_folder> -e <error_dir>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            input_file = arg
        elif opt in ("-o", "--ofolder"):
            output_dir = arg
        elif opt in ("-e", "--efolder"):
            error_dir = arg
    print('\n\n')
    print(input_file)
    print(output_dir)
    print(error_dir)
    print('\n\n')
    return (input_file, output_dir, error_dir)

            
def read_hashes(input_file):
        h_list = []
        with open(input_file, 'r') as hash_list:
            for line in hash_list:
                #Strip the \n off the hashes
                h_list = [line[:-1] for line in hash_list]
        return h_list


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
