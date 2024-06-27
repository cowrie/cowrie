import json
from model.cowrie_handler import CowrieHandler
from model.llm import LLM, FakeLLM
import os

RESPONSE_PATH = "/cowrie/cowrie-git/src/model/static_responses.json"

class ResponseHandler():
    def __init__(self, protocol) -> None:
        protocol.fs.rh = self
        self.ch = CowrieHandler(protocol)
        if os.environ["COWRIE_USE_LLM"].lower() == "true":
            print("using real llm")
            self.llm = LLM()
        else:
            print("using fake llm")
            self.llm = FakeLLM()


        with open(RESPONSE_PATH) as response_file:
            self.response_dict = json.load(response_file)

    
    def ls_respond(self,
                   path: str):
        resp = self.find_static_response("ls", "", path)
        if resp is None:
            resp = self.llm.generate_response("ls")
        
        #Should maybe be just for new LLM generations?
        print("RESPONSE!!")
        print(resp)
        print("------")
        self.ch.enforce_ls(path, resp)

    def netstat_respond(self):
        resp = self.find_static_response("netstat")
        if resp is None:
            resp = self.llm.generate_response("netstat")
        print("RESPONSE!!")
        print(resp)
        print("------")
        return resp
        
    def ifconfig_respond(self):
        resp = self.find_static_response("ifconfig")
        if resp is None:
            resp = self.llm.generate_response("ifconfig")
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
        resp = self.find_static_response("file_contents", "", path)
        if resp is None:
            resp = "fake file contents in "+path
        self.ch.enforce_file_contents(path, resp)
        return resp
