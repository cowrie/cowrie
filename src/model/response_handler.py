import json
from llm import get_llm_response

RESPONSE_PATH = "/cowrie/cowrie-git/src/model/static_responses.json"


class ResponseHandler():
    def __init__(self) -> None:
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

        cmd = "pwd"
        resp = self.find_static_response(cmd, flags, path)
        if resp is None:
            resp = get_llm_response(cmd)
        else:
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

