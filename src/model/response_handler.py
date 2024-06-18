import json
from model.cowrie_handler import CowrieHandler
from model.llm import cowrie_llm

RESPONSE_PATH = "/cowrie/cowrie-git/src/model/static_responses.json"

class ResponseHandler():
    def __init__(self, fs) -> None:
        fs.rh = self
        self.ch = CowrieHandler(fs)

        with open(RESPONSE_PATH) as response_file:
            self.response_dict = json.load(response_file)

    
    def ls_respond(self,
                   path: str,
                   flag_l=False,
                   flag_a=False,
                   flag_d=False):
        flags = ""
        if flag_l:
            flags = flags+"-l"
        if flag_a:
            flags = flags+"-a"
        if flag_d:
            flags = flags+"-d"

        resp = self.find_static_response("ls", flags, path)
        #resp = cowrie_llm.generate_response("ls")

        if resp is None:
            resp = cowrie_llm.generate_response("ls")
        
        #Should maybe be just for new LLM generations?
        print("RESPONSE!!")
        print(resp)
        print("------")
        self.ch.enforce_ls(path, resp)

        return resp

    def netstat_respond(self):
        resp = cowrie_llm.generate_response("netstat")
        print("RESPONSE!!")
        print(resp)
        print("------")
        return resp
        
    def ifconfig_respond(self):
        resp = cowrie_llm.generate_response("ifconfig")
        print("RESPONSE!!")
        print(resp)
        print("------")
        return resp

    def find_static_response(self,
                      command:str,
                      flags: list[str] = "",
                      path: None | str = None
                      ):
        if path is not None:
            try:
                return self.response_dict[command][flags][path]
            except Exception:
                return None
        else:
            try:
                return self.response_dict[command][flags]
            except Exception:
                return None
            
    def file_contents_respond(self, path: str):
        print("Path:", path)
        return "fake file contents in "+path
