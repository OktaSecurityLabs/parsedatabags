#!/usr/bin/env python

import json
import sys
import os
import base64
import binascii

class parse_data_bags():

    def __init__(self, a_directory):
        self.a_dir = a_directory
        self.final_results = {}
        self.parse_directory()
        self.print_final_results()

    def print_dict(self, a_dict):
        for key, value in a_dict.iteritems():
            if not u'encrypted_data' in key and not '.json' in key:
                self.count += 1
            
            if type(value) == dict:
                self.print_dict(value)
            
            try:
                base64.decodestring(value)
                continue
            except:
                continue

    def print_final_results(self):
        self.count = 0
        self.print_dict(self.final_results)
        print "Total number of affected files with weak encrypted values: %s" % len(self.final_results)
        print "Number of values <=12 in length in data bags: %s" % self.count

    def parse_directory(self):
        for self.dirName, self.subdirList, self.fileList in os.walk(self.a_dir):
            for self.fname in self.fileList:
                if 'json' in self.fname:
                    print '[*] Parsing Json file: %s' % os.path.realpath(os.path.join(self.dirName, self.fname))
                    self.ingest_json()
                    self.check_parameters()
            
    def ingest_json(self):
        self.json_string = ''
        self.parsed_json = ''
        
        with open(os.path.realpath(os.path.join(self.dirName, self.fname)), 'r') as f:
            self.json_string = f.read()
            self.parsed_json = json.loads(self.json_string)
    
    def parse_dict(self, a_dict):
            
        for key, value in a_dict.iteritems(): 
            if 'pass' in key.lower() or 'key' in key.lower():
                self._temp = key 
                self.tracker = True
            
            if key == 'encrypted_data': 
                enc_blob = base64.b64decode(value.replace('\n', ''))
                max_size_enc_data = len(enc_blob) - 20
                
                if max_size_enc_data == 12:
                    min_size_enc_data = 0
                else:
                    min_size_enc_data = max_size_enc_data - 15     
                
                print "  [*] Data_bag:", self.prior_key 
                print "\t[*] Max size plaintext: {0} bytes; Min size of plaintext: {1} bytes".format(max_size_enc_data, min_size_enc_data)
                
                if len(value.replace('\n', '')) <= 44:
                    print "\t[*] Weak encrypted value!"
                    self.results[self._temp] =  {key: value}
                    self._temp = ''
            
            self.prior_key = key   
            
            if type(value) == dict:
                self.parse_dict(value)
            
            self.tracker = False
            self._temp = ''
 
    def check_parameters(self):
        #parse the entire json structure:
        self.results = {}
        self.tracker = False
        self._temp = ''
        self.prior_key = ''

        self.parse_dict(self.parsed_json)

        if self.results != {}:
            self.final_results[os.path.realpath(os.path.join(self.dirName, self.fname))] = self.results

if __name__ == "__main__":
    if len(sys.argv) !=2:
        print('Usage:', sys.argv[0], 'directory of data bags')
        sys.exit(-1)

    parse_data_bags(sys.argv[1])
