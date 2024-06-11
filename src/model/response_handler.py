import json

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

        responses = self.response_dict["ls"]
        if flags in responses.keys():
            responses = responses[flags]
        else:
            return "Some new flags I don't have, maybe command not recognized"

        if path in responses.keys():
            return responses[path]
        else:
            return "Some new ls-view I don't have"
        