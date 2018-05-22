from twisted.python import log
import cowrie.core.output
from cowrie.core.config import CONFIG
from ConfigParser import NoOptionError

import requests


class Output(cowrie.core.output.Output):
    enabled = True
    viper_host = ''
    viper_port = 0
    viper_project = ''
    viper_token = ''
    
    
    def __init__(self):
        try:
            self.viper_host = CONFIG.get('output_viper', 'host')
            self.viper_port = CONFIG.get('output_viper', 'port')
            self.viper_project = CONFIG.get('output_viper', 'project')
            self.viper_token = CONFIG.get('output_viper', 'token')
        except NoOptionError:
            self.enabled = False

        cowrie.core.output.Output.__init__(self)

    def start(self):
        if not self.viper_host:
            raise Exception('output_viper: Missing parameter(s) in configuration')

    def stop(self):
        pass

    def write(self, entry):
        # It intercepts only file downloads
        if entry["eventid"] != "cowrie.session.file_download" or not self.enabled:
            return
        
        files = {'file': open(entry['outfile'], 'rb')}
        
        try:
            res = requests.request(
                method = "POST",
                url = "http://{}:{}/api/v3/project/{}/malware/upload/".format(self.viper_host, self.viper_port, self.viper_project),
                headers = {'Authorization': 'Token {}'.format(self.viper_token)},
                files=files,
                timeout = 10)
            if res and res.ok:
                print('output_viper: Sample sent to Viper')
            else:
                response = res.json()
                if 'error' in response:
                    if response['error']['code'] == 'DuplicateFileHash':
                        print("output_viper: Sample already available in project")
                else:
                    print("output_viper: Error! Request failed: {}".format(res.status_code))
        except Exception as e:
            print("output_viper: Error! Request failed: {}".format(e))
        return
