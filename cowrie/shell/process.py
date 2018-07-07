import json

class CommandOutputParser:

    def getCommandOutput(self, file):
        with open(file) as f:
            cmdoutput = json.load(f)
        return cmdoutput
