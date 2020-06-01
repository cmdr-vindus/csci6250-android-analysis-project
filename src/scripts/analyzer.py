import argparse
import json
import csv
import os
import pandas as pd
from mlxtend.preprocessing import TransactionEncoder
from mlxtend.frequent_patterns import association_rules, fpgrowth
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
import collections


class Analyzer:

    def __init__(self):
        self.data = self.read_json()
        self.genre_list = ["BUSINESS","SOCIAL","ENTERTAINMENT","PRODUCTIVITY",
                      "EDUCATION", "VIDEO_PLAYERS", "NEWS_AND_MAGAZINES",
                      "PHOTOGRAPHY", "COMMUNICATION", "MUSIC_AND_AUDIO",
                      "TOOLS", "TRAVEL_AND_LOCAL", "GAME"]
        

    def get_data_path(self):
        home = str(Path.home())
        dir_path = os.path.join(home, "workspace/csci6250-android-analysis-project/src/data/gplay-trim-json")
        return dir_path

    
    def read_json(self):
        data_path = self.get_data_path()
        files = []
        # r = root, d = directories, f = files
        for r, d, f in os.walk(data_path):
            for file in f:
                if '.json' in file:
                    files.append(os.path.join(r, file))

        json_data = {}
        for file in files:
            with open(file) as json_file:
                data = json.load(json_file)
                if 'package_name' in data:
                    app_name = data['package_name']
                    json_data[app_name] = data
                else:
                    print(file)
        return json_data
    
    
    # First level key: pass the key in the json to look for
    # returns the collection of the list found in the params
    # Params Ex: security_score, average_cvss

    def get_defined_key_found_values(self, param):
        collector = []
        for key, value in self.data.items():
            if param in value:
                collector.append(value[param])
        return collector

    def data_converter(self, input, type_converter):
        if "float" in type_converter:
            return float(input)
        elif "int" in type_converter:
            return int(input)

        elif "str" in type_converter:
            return str(input)

        else:
            raise Exception("Unsupported case")

    def refine_collector(self, param, refine_text=None, data_type=None):
        refined_collector = []
        for val in param:
            val = val.split(refine_text)
            text_refined = val[0]
            if refine_text is not None and data_type is not None:
                text_refined = self.data_converter(text_refined, data_type)
                refined_collector.append(text_refined)
        return refined_collector

    def get_permissions_dangerous_count_info(self):
        found_permissions = self.get_defined_key_found_values("permissions")
        permissions = {}
        for value in found_permissions:
            for k, v in value.items():
                if k not in permissions:
                    if "dangerous" in v['status']:
                        splitter = k.split(".")
                        permission_value = splitter[len(splitter)-1]
                        if permission_value in permissions:
                            permissions[permission_value] = permissions[permission_value] + 1
                        else:
                            permissions[permission_value] = 1
        return permissions

    def get_certificate_analysis_good_and_bad_count(self):
        found_certificates = self.get_defined_key_found_values("certificate_analysis")
        certificates = {}
        for value in found_certificates:
            for k, v in value.items():
                if "certificate_status" in k:
                    category = v
                    if category in certificates:
                        certificates[category] = certificates[category] + 1
                    else:
                        certificates[category] = 1
        return certificates

    def cwe_count(self):
        found_code_analysis = self.get_defined_key_found_values("code_analysis")
        cwe = {}
        for value in found_code_analysis:
            for k, v in value.items():
                if "cwe" in v:
                    if v['cwe'] in cwe:
                        cwe[v['cwe']] = cwe[v['cwe']] + 1
                    else:
                        cwe[v['cwe']] = 1
        return cwe

    def get_code_analysis(self, genre=None):
        if genre is None:
            return {
                'cwe_info': self.cwe_count()
                }
        else:
            return {
                genre+'_cwe_info': self.cwe_count_by_genre(genre)
                }
    
    def headers_code_analysis(self):
        found_code_analysis = self.get_defined_key_found_values("code_analysis")
        #print('found_code_analysis : '+str(type(found_code_analysis)))
        
        code_headers = {}
        code_items_list = []
        for subdict in found_code_analysis:
            #print(subdict)
            #print('value : '+str(type(value)))
            for header in subdict:
                if header in code_headers:
                    code_headers[header] = code_headers[header] + 1
                else:
                    code_headers[header] = 1
            '''
            for k,v in subdict.items():
                if "path" in k:
                    instances = len(v)
                    if 'count' in code_items:
                        code_items['count'] = code_items['count'] + instances
                    else:
                        code_items['count'] = instances
                
                if "level" in k:
                    code_items['level'] = v
                if "cvss" in k:
                    code_items['cvss'] = v
                if 'cwe' in k:
                    code_items['cwe'] = v
                if 'owasp' in k:
                    code_items['owasp'] = v
            '''
                #code_items_list.append(code_items)
                #code_items.clear()
        print(json.dumps(code_headers, indent=4))
        return code_headers
    
    def levels_code_analysis(self):
        found_code_analysis = self.get_defined_key_found_values("code_analysis")
        levels_collector = []
        code_levels = {}
        for subdict in found_code_analysis:
            levels_collector.append(self.extract_values(subdict, 'level'))
            
        for section in levels_collector:
            for level in section:
                if level in code_levels:
                    code_levels[level] = code_levels[level] + 1
                else:
                    code_levels[level] = 1
            
        print(json.dumps(code_levels, indent=4))
        return code_levels

    def owasp_code_analysis(self):
        found_code_analysis = self.get_defined_key_found_values("code_analysis")
        owasp_collector = []
        code_owasps = {}
        for subdict in found_code_analysis:
            owasp_collector.append(self.extract_values(subdict, 'owasp'))
            
        for section in owasp_collector:
            for owasp in section:
                if owasp in code_owasps:
                    code_owasps[owasp] = code_owasps[owasp] + 1
                else:
                    code_owasps[owasp] = 1
                    
        print(json.dumps(code_owasps, indent=4))
        return code_owasps
    
    def cvss_code_analysis(self):
        found_code_analysis = self.get_defined_key_found_values("code_analysis")
        cvss_collector = []
        code_cvss = {}
        for subdict in found_code_analysis:
            cvss_collector.append(self.extract_values(subdict, 'cvss'))
            
        for section in cvss_collector:
            for cvss in section:
                if cvss in code_cvss:
                    code_cvss[cvss] = code_cvss[cvss] + 1
                else:
                    code_cvss[cvss] = 1
                    
        print(json.dumps(code_cvss, indent=4))
        return code_cvss
    
    def deep_code_analysis(self):
        found_code_analysis = self.get_defined_key_found_values("code_analysis")
        code_analysis_collector = []
        code_dict = {}
        offense = None
        for subdict in found_code_analysis:
            for header in subdict:
                offense = header
                if header not in code_dict:
                    code_dict['offense'] = offense
                #assuming it is in the dictionary
                code_dict['app_occ'] = len(self.extract_values(subdict, offense))
                
                if 'occurances' in code_dict:
                    code_dict['occurances'] = code_dict['occurances'] + len(self.extract_values(subdict,'path'))
                else:
                    code_dict['occurances'] = len(self.extract_values(subdict,'path'))
                    
                print(json.dumps(code_dict, indent=4))
        return
    
    def generate_offense_list(self):
        found = self.get_defined_key_found_values("code_analysis")
        offense_list = []
        for subdict in found:
            for header in subdict:
                if header not in offense_list:
                    offense_list.append(header)
        thing = self.extract_values(self.data, offense_list[1])
        print(thing)
        return offense_list
    
    def get_file_analysis(self):
        found_file_analysis = self.get_defined_key_found_values("file_analysis")
        hardcoded_items = {}
        for value in found_file_analysis:
            for subdict in value:
                offense = None
                for k, v in subdict.items():
                    if "finding" in k:
                        offense = v.split()[0]
                        if offense in hardcoded_items:
                            hardcoded_items[offense] = hardcoded_items[offense] + 1
                        else:
                            hardcoded_items[offense] = 1
                for k,v in subdict.items():
                    if "files" in k:
                        instances = len(v)
                        if offense.split()[0]+str("-LEN") in hardcoded_items:
                            hardcoded_items[offense.split()[0]+str("-LEN")] = hardcoded_items[offense.split()[0]+str("-LEN")] + instances
                        else:
                            hardcoded_items[offense.split()[0]+str("-LEN")] = instances
        return hardcoded_items
    
    def get_file_analysis_by_genre(self, genre):
        appIDs = self.get_appIDs_by_genre(genre)
        hardcoded_items ={}
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            file_analysis_list = self.get_defined_key_reduced(app_dict,"file_analysis")
            for value in file_analysis_list:
                for subdict in value:
                    offense = None
                    for k,v in subdict.items():   
                        if "finding" in k:
                            offense = v.split()[0]
                            if offense in hardcoded_items:
                                hardcoded_items[offense] = hardcoded_items[offense] + 1
                            else:
                                hardcoded_items[offense] = 1
                    for k,v in subdict.items():
                        if "files" in k:
                            instances = len(v)
                            if offense.split()[0]+str("-LEN") in hardcoded_items:
                                hardcoded_items[offense.split()[0]+str("-LEN")] = hardcoded_items[offense.split()[0]+str("-LEN")] + instances
                            else:
                                hardcoded_items[offense.split()[0]+str("-LEN")] = instances
        return hardcoded_items
    

    def get_genre_count_info(self):
        found_play_store_details = self.get_defined_key_found_values("playstore_details")
        game_genres = ["GAME_ARCADE","GAME_SIMULATION","GAME_PUZZLE","GAME_CASUAL",
                       "GAME_ACTION","GAME_TRIVIA","GAME_CARD","GAME_WORD","GAME_RACING",
                       "GAME_ROLE_PLAYING", "GAME_MUSIC", "GAME_CASINO", "GAME_BOARD",
                       "GAME_SPORTS", "GAME_STRATEGY", "GAME_ADVENTURE"]
        genre_info = {}
        for value in found_play_store_details:
            for k, v in value.items():
                if "genreId" in k:
                    genre_id = v
                    if genre_id in game_genres:
                        genre_id = "GAME"
                    if genre_id not in genre_info:
                        genre_info[genre_id] = 1
                    else:
                        genre_info[genre_id] = genre_info[genre_id] + 1
        return genre_info
    
    def get_app_score(self):
        found_play_store_details = self.get_defined_key_found_values("playstore_details")
        score_info = []
        for value in found_play_store_details:
            for k, v in value.items():
                if "score" in k:
                    score_info.append(v)
        return score_info
    
    def get_appIDs_by_genre(self, genre):
        found_play_store_details = self.get_defined_key_found_values("playstore_details")
        game_genres = ["GAME_ARCADE","GAME_SIMULATION","GAME_PUZZLE","GAME_CASUAL",
                       "GAME_ACTION","GAME_TRIVIA","GAME_CARD","GAME_WORD","GAME_RACING",
                       "GAME_ROLE_PLAYING", "GAME_MUSIC", "GAME_CASINO", "GAME_BOARD",
                       "GAME_SPORTS", "GAME_STRATEGY", "GAME_ADVENTURE"]
        collector = []
        for value in found_play_store_details:
            for k, v in value.items():
                if "genreId" in k:
                    if genre == v:
                        app_name = value["appId"]
                        collector.append(app_name)
                    elif genre == "GAME":
                        if v in game_genres:
                            app_name = value["appId"]
                            collector.append(app_name)
        return collector
    
    def get_data_by_appID(self, appID_list):
        collector = []
        for k,v in self.data.items():
            if k in appID_list:
                collector.append(self.data[k])
        return collector

    def get_app_data_by_genre(self, genre):
        appID_by_genre = self.get_appID_by_genre(genre)
        #print(appID_by_genre)
        app_data = self.get_data_by_appID(appID_by_genre)
        return app_data
    
    def get_defined_key_reduced(self, genre_specific, param):
        collector = []
        for k, v in genre_specific.items():
            if param in k:
                collector.append(genre_specific[k])
        return collector    
   
    def permissions_by_genre(self, genre):
        appIDs = self.get_appIDs_by_genre(genre)
        permissions = {}
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            perm_list = self.get_defined_key_reduced(app_dict, "permissions")
            for value in perm_list:
                for k,v in value.items():
                    if k not in permissions:
                        if "dangerous" in v['status']:
                            splitter = k.split(".")
                            permission_value = splitter[len(splitter)-1]
                            if permission_value in permissions:
                                permissions[permission_value] = permissions[permission_value] + 1
                            else:
                                permissions[permission_value] = 1
        return permissions 
    
    def certificate_analysis_by_genre(self, genre):
        appIDs = self.get_appIDs_by_genre(genre)
        certs = {}
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            cert_list = self.get_defined_key_reduced(app_dict, "certificate_analysis")
            for value in cert_list:
                for k,v in value.items():
                    if "certificate_status" in k:
                        category = v
                        if category in certs:
                            certs[category] = certs[category] + 1
                        else:
                            certs[category] = 1
        return certs
    
    def cwe_count_by_genre(self, genre):
        appIDs = self.get_appIDs_by_genre(genre)
        cwe = {}
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            cwe_list = self.get_defined_key_reduced(app_dict, "code_analysis")
            for value in cwe_list:
                for k, v in value.items():
                    if "cwe" in v:
                        if v['cwe'] in cwe:
                            cwe[v['cwe']] = cwe[v['cwe']] + 1
                        else:
                            cwe[v['cwe']] = 1
        return cwe
    
    def create_cwe_matrix_by_genre(self, genre):
        appIDs = self.get_appIDs_by_genre(genre)
        output_file = open('../data/cwe-baskets/'+genre.lower()+'_cwe.csv','w')
        csv_writer = csv.writer(output_file, dialect='excel')
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            cwe_list = self.get_defined_key_reduced(app_dict, "code_analysis")
            output_list = []
            for value in cwe_list:
                for k, v in value.items():
                    if "cwe" in v:
                        if v['cwe'] != "":
                            output_list.append(v['cwe'])
            
            csv_writer.writerow(output_list)
        output_file.close()
        return
    
    def create_cwe_matrix_all(self):
        output_file = open('../data/cwe-baskets/all_cwe.csv','w')
        csv_writer = csv.writer(output_file, dialect='excel')
        appIDs = self.data.keys()
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            cwe_list = self.get_defined_key_reduced(app_dict, "code_analysis")
            output_list = []
            for value in cwe_list:
                for k, v in value.items():
                    if "cwe" in v:
                        if v['cwe'] != "":
                            output_list.append(v['cwe'])
                            
            csv_writer.writerow(output_list)
        output_file.close()
        return
    
    def create_permissions_matrix_by_genre(self, genre):
        appIDs = self.get_appIDs_by_genre(genre)
        output_file = open('../data/permission-baskets/'+genre.lower()+'_permissions.csv','w')
        csv_writer = csv.writer(output_file, dialect='excel')
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            permissions_list = self.get_defined_key_reduced(app_dict, "permissions")
            output_list = []
            for value in permissions_list:
                for k, v in value.items():
                    #if "dangerous" in v['status']:
                    splitter = k.split(".")
                    permission_value = splitter[len(splitter)-1]
                    output_list.append(permission_value)
            
            csv_writer.writerow(output_list)
        output_file.close()
        return
    
    def create_permissions_matrix_all(self):
        output_file = open('../data/permission-baskets/all_permissions.csv','w')
        csv_writer = csv.writer(output_file, dialect='excel')
        appIDs = self.data.keys()
        for singular_app in appIDs:
            app_dict = self.data[singular_app]
            permissions_list = self.get_defined_key_reduced(app_dict, "permissions")
            output_list = []
            for value in permissions_list:
                for k, v in value.items():
                    #if "dangerous" in v['status']:
                    splitter = k.split(".")
                    permission_value = splitter[len(splitter)-1]
                    output_list.append(permission_value)
                        
            csv_writer.writerow(output_list)
        output_file.close()
        return
    
    def generate_cwe_csv(self, genre_list):
        self.create_cwe_matrix_all()
        for genre in genre_list:
            self.create_cwe_matrix_by_genre(genre)
        return
    
    def generate_permissons_csv(self, genre_list):
        self.create_permissions_matrix_all()
        for genre in genre_list:
            self.create_permissions_matrix_by_genre(genre)
        return
    
    
    def load_baskets_csv(self, input_csv):
        data = []
        
        with open(input_csv, 'r') as read_obj:
            csv_reader = csv.reader(read_obj)
            data = list(csv_reader)
        #Would breakout here if deciding to use
        #other apriori lib
        
        #Encoding CWE Baskets as
        #an sparse matrix
        te = TransactionEncoder()
        te_ary = te.fit(data).transform(data)
        df = pd.DataFrame(te_ary, columns=te.columns_)
        
        return df
    
    def auto_rule_generation(self, genre_list):
        genre_list.append('all')
        for genre in genre_list:
            cwe_input = '../data/cwe-baskets/'+genre.lower()+'_cwe.csv'
            cwe_output ='../data/cwe-rules/'+genre.lower()+'_cwe_rules'
            perm_input='../data/permission-baskets/'+genre.lower()+'_permissions.csv'
            perm_output='../data/permission-rules/'+genre.lower()+'_permission_rules'
            self.run_fpgrowth(input_csv=cwe_input, output_file=cwe_output, min_threshold=0.6)
            self.run_fpgrowth(input_csv=perm_input, output_file=perm_output, min_threshold=0.6)
        return
    
    def auto_rule_trim(self, genre_list):
        for genre in genre_list:
            cwe_input = '../data/cwe-rules/'+genre.lower()+'_cwe_rules.csv'
            cwe_output = '../data/cwe-rules-filtered/'+genre.lower()+'_cwe_filtered'
            perm_input = '../data/permission-rules/'+genre.lower()+'_permission_rules.csv'
            perm_output = '../data/permission-rules-filtered/'+genre.lower()+'_permission_filtered'
            self.convert_to_excel(input_csv=cwe_input, output_file=cwe_output)
            self.convert_to_excel(input_csv=perm_input, output_file=perm_output)
        return
    
    def convert_to_excel(self, input_csv, output_file):
         df = pd.read_csv(input_csv)
         df = df.iloc[::2]
         #trim_frame = self.trim_dataframe(df)
         #trim_frame.to_excel(output_file+".xlsx", index=False)
         df.to_excel(output_file+'.xlsx', index=False)
         return
         

    def run_fpgrowth(self, input_csv, output_file, min_threshold):
        target_df = self.load_baskets_csv(input_csv)
        results = fpgrowth(target_df, min_support=min_threshold, use_colnames=True)
        
        rules = self.run_association_rules(results, 0.7)
        rules["antecedent_len"] = rules["antecedents"].apply(lambda x: len(x))
        rules["consequent_len"] = rules["consequents"].apply(lambda x: len(x))
        combo_col = rules["antecedent_len"]+rules["consequent_len"]
        rules["combo_len"] = combo_col
        max_combo_len = rules["combo_len"].max()
        rules.drop(['antecedent support', 'consequent support'], axis=1, inplace=True)
        
        '''
        #Attempting to make Maximal Rule sets
        save = rules[ (rules["confidence"] > 0.75) &
                     (rules["lift"] > 1.0)&
                     (rules["combo_len"] == max_combo_len)
            ]
        '''
        save = rules[(rules["confidence"] > 0.75)]
        save.sort_values(["lift"], ascending=False, inplace=True)
        #save.sort_values(["support","lift"], ascending=False, inplace=True)
        save.to_csv(output_file+".csv", index= False)
        
        return results

    def run_association_rules(self, results_df, threshold):
        rules = association_rules(results_df, metric="confidence", min_threshold=threshold)
        return rules

    def process(self):

        self.generate_cwe_csv(self.genre_list)
        self.generate_permissons_csv(self.genre_list)
        
        self.auto_rule_generation(self.genre_list)
        self.auto_rule_trim(self.genre_list)
        
        average_cvss = self.get_defined_key_found_values("average_cvss")
        security_score = self.get_defined_key_found_values("security_score")
        raw_apk_size = self.get_defined_key_found_values("size")
        apk_size = self.refine_collector(raw_apk_size, refine_text="MB", data_type="float")
        app_scores = self.get_app_score()
        
        info = {
            'average_cvss_quartile_info': self.get_quartiles(average_cvss, "Average CSVSS Score"),
            'average_security_score_quartile_info': self.get_quartiles(security_score, "The MobSF Security Score"),
            'average_apk_size': self.get_quartiles(apk_size, "APK Sizes in MB"),
            'permission_dangerous_count': self.get_permissions_dangerous_count_info(),
            'all_file_analysis': self.get_file_analysis(),
            'all_cert_analysis': self.get_certificate_analysis_good_and_bad_count(), #May want to change string for easy keyin
            'all_code_analysis': self.get_code_analysis(),
            'genre_info': self.get_genre_count_info(),
            'playstore_scores': self.get_quartiles(app_scores, "Playstore Scores"),
            'business_dangerous_permissions': self.permissions_by_genre("BUSINESS"),
            'business_file_analysis': self.get_file_analysis_by_genre("BUSINESS"),
            'business_cert_analysis': self.certificate_analysis_by_genre("BUSINESS"),
            'business_code_analysis': self.cwe_count_by_genre('BUSINESS'),
            'social_dangerous_permissions': self.permissions_by_genre('SOCIAL'),
            'social_file_analysis': self.get_file_analysis_by_genre("SOCIAL"),
            'social_cert_analysis': self.certificate_analysis_by_genre('SOCIAL'),
            'social_code_analysis': self.cwe_count_by_genre('SOCIAL'),
            'entertainment_dangerous_permissions': self.permissions_by_genre('ENTERTAINMENT'),
            'entertainment_file_analysis': self.get_file_analysis_by_genre("ENTERTAINMENT"),
            'entertainment_cert_analysis': self.certificate_analysis_by_genre('ENTERTAINMENT'),
            'entertainment_code_analysis': self.cwe_count_by_genre('ENTERTAINMENT'),
            'productivity_dangerous_permissions': self.permissions_by_genre('PRODUCTIVITY'),
            'productivity_file_analysis': self.get_file_analysis_by_genre("PRODUCTIVITY"),
            'productivity_cert_analysis': self.certificate_analysis_by_genre('PRODUCTIVITY'),
            'productivity_code_analysis': self.cwe_count_by_genre('PRODUCTIVITY'),
            'education_dangerous_permissions': self.permissions_by_genre('EDUCATION'),
            'education_file_analysis': self.get_file_analysis_by_genre("EDUCATION"),
            'education_cert_analysis': self.certificate_analysis_by_genre('EDUCATION'),
            'education_code_analysis': self.cwe_count_by_genre('EDUCATION'),
            'video_players_dangerous_permissions': self.permissions_by_genre('VIDEO_PLAYERS'),
            'video_players_file_analysis': self.get_file_analysis_by_genre("VIDEO_PLAYERS"),
            'video_players_cert_analysis': self.certificate_analysis_by_genre('VIDEO_PLAYERS'),
            'video_players_code_analysis': self.cwe_count_by_genre('VIDEO_PLAYERS'),
            'news_and_magazines_dangerous_permissions': self.permissions_by_genre('NEWS_AND_MAGAZINES'),
            'news_and_magazines_analysis': self.get_file_analysis_by_genre("NEWS_AND_MAGAZINES"),
            'news_and_magazines_cert_analysis': self.certificate_analysis_by_genre('NEWS_AND_MAGAZINES'),
            'news_and_magazines_code_analysis': self.cwe_count_by_genre('NEWS_AND_MAGAZINES'),
            'photography_dangerous_permissions': self.permissions_by_genre('PHOTOGRAPHY'),
            'photography_file_analysis': self.get_file_analysis_by_genre("PHOTOGRAPHY"),
            'photography_cert_analysis': self.certificate_analysis_by_genre('PHOTOGRAPHY'),
            'photography_code_analysis': self.cwe_count_by_genre('PHOTOGRAPHY'),
            'communication_dangerous_permissions': self.permissions_by_genre('COMMUNICATION'),
            'communication_file_analysis': self.get_file_analysis_by_genre("COMMUNICATION"),
            'communication_cert_analysis': self.certificate_analysis_by_genre('COMMUNICATION'),
            'communication_code_analysis': self.cwe_count_by_genre('COMMUNICATION'),
            'music_and_audio_dangerous_permissions': self.permissions_by_genre('MUSIC_AND_AUDIO'),
            'music_and_audio_file_analysis': self.get_file_analysis_by_genre("MUSIC_AND_AUDIO"),
            'music_and_audio_cert_analysis': self.certificate_analysis_by_genre('MUSIC_AND_AUDIO'),
            'music_and_audio_code_analysis': self.cwe_count_by_genre('MUSIC_AND_AUDIO'),
            'tools_dangerous_permissions': self.permissions_by_genre('TOOLS'),
            'tools_file_analysis': self.get_file_analysis_by_genre("TOOLS"),
            'tools_cert_analysis': self.certificate_analysis_by_genre('TOOLS'),
            'tools_code_analysis': self.cwe_count_by_genre('TOOLS'),
            'travel_and_local_dangerous_permissions': self.permissions_by_genre('TRAVEL_AND_LOCAL'),
            'travel_and_local_file_analysis': self.get_file_analysis_by_genre("TRAVEL_AND_LOCAL"),
            'travel_and_local_cert_analysis': self.certificate_analysis_by_genre('TRAVEL_AND_LOCAL'),
            'travel_and_local_code_analysis': self.cwe_count_by_genre('TRAVEL_AND_LOCAL'),
            'game_dangerous_permissions': self.permissions_by_genre("GAME"),
            'game_file_analysis': self.get_file_analysis_by_genre("GAME"),
            'game_cert_analysis': self.certificate_analysis_by_genre("GAME"),
            'game_code_analysis': self.cwe_count_by_genre("GAME")
        }

        print(json.dumps(info, indent=4))
        with open('../data/info.json', 'w') as f:
            json.dump(info, f)
            
        return
        

    def get_quartiles(self, collection, description):
        create_pd = pd.DataFrame(collection, columns=['col_name'], index=None)
        describe_col = create_pd.col_name.describe()
        convert_data_to_dictionary = describe_col.to_dict()

        count = convert_data_to_dictionary['count']
        mean = convert_data_to_dictionary['mean']
        min = convert_data_to_dictionary['min']
        std = convert_data_to_dictionary['std']
        percentile_25th = convert_data_to_dictionary['25%']
        percentile_50th = convert_data_to_dictionary['50%']
        percentile_75th = convert_data_to_dictionary['75%']
        percentile_90th = create_pd.col_name.quantile(0.9)
        percentile_99th = create_pd.col_name.quantile(0.99)
        max = convert_data_to_dictionary['max']

        quartiles_info = {
            'Description': description,
            'std': std,
            'count': count,
            'mean': mean,
            'min': min,
            'max': max,
            '25%': percentile_25th,
            '50%': percentile_50th,
            '75%': percentile_75th,
            '90%': percentile_90th,
            '99%': percentile_99th
        }

        return quartiles_info
    
    def data_visualizations(self):
        with open('../data/info.json', 'r') as f:
            info_data = json.load(f)
        
        sns.set(context='talk', font_scale=0.85)
    
       
        cert_key_list = [x.lower()+'_cert_analysis' for x in self.genre_list]
        for genre in cert_key_list:
            frame = self.dict_to_df(info_data[genre])
            frame = frame.sort_values('Category')
            self.plot_bar_chart(frame, title=genre, xlabel='Category', ylabel='Count',
                                palette={"good":"g","warning":"y","bad":"r"})
       
        
        code_key_list = [x.lower()+'_code_analysis' for x in self.genre_list]
        for genre in code_key_list:
            if genre == 'all_code_analysis':
                frame = self.dict_to_df(info_data[genre]['cwe_info'])
                frame = frame.sort_values('Category')
                self.plot_bar_chart(frame, title=genre, xlabel='Category', ylabel='Count', palette='Set1')
            else:
                frame = self.dict_to_df(info_data[genre])
                frame = frame.sort_values('Category')
                self.plot_bar_chart(frame, title=genre, xlabel='Category', ylabel='Count', palette='Set1')
        
        return
    
    def dict_to_df(self, data):
        df = pd.DataFrame(list(data.items()), columns=['Category','Count'])
        return df
    
    def plot_bar_chart(self, df_data, title, xlabel, ylabel, palette):
        
        plt.figure(figsize=(10,10))
        
        plt.title(title)
        chart = sns.barplot(x=df_data['Category'], y=df_data['Count'], palette=palette)
        chart.set_xticklabels(chart.get_xticklabels(), rotation=45,
                              horizontalalignment='right', fontweight='light',
                              fontsize='small')
        
        fig= chart.get_figure()
        path='../data/plots/'
        if '_cert_analysis' in title:
            path = '../data/plots/cert_analysis_plots/'
        elif '_code_analysis' in title:
            path='../data/plots/code_analysis_plots/'
        fig.savefig(path+title+'_plot.png')
        
        #Needed for memory consumption
        plt.clf()
        plt.close()
        return
    
    def trim_dataframe(self, data):
        data.drop(["antecedent_len","consequent_len","combo_len"], axis=1, inplace=True)
        pd.set_option('precision', 4)
        data.sort_values(["lift"], ascending=False, inplace=True)
        trim_data = data.head(5)
        return trim_data
        
    def extract_values(self, obj, key):
        """Pull all values of specified key from nested JSON."""
        arr = []

        def extract(obj, arr, key):
            """Recursively search for values of key in JSON tree."""
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        extract(v, arr, key)
                    elif k == key:
                        arr.append(v)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item, arr, key)
            return arr

        results = extract(obj, arr, key)
        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Program for the analyzer code to run")

    parser.add_argument('-a', '--analyze-type',
                        action='store',
                        required=False,
                        help='The type of the analyze report to investigate')

    args = parser.parse_args()

    analyze = Analyzer()
    #analyze.get_file_analysis()
    
    #analyze.process()
    '''
    analyze.headers_code_analysis()
    analyze.levels_code_analysis()
    analyze.owasp_code_analysis()
    analyze.cvss_code_analysis()
    '''
    #analyze.deep_code_analysis()
    analyze.generate_offense_list()
    
    #analyze.data_visualizations()
