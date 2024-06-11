import json

RESPONSE_PATH = "/cowrie/cowrie-git/src/model/static_responses.json"


class ResponseHandler():
    def __init__(self) -> None:
        with open(RESPONSE_PATH) as response_file:
            self.response_dict = json.load(response_file)

    
    def respond(self, command: str):
        if command in self.response_dict.keys():
            return self.response_dict[command]
        else:
            return "Unknown command"
        