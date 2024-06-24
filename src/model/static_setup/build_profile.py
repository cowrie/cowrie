import sys
sys.path.append("/cowrie/cowrie-git/src")

from model.llm import LLM, FakeLLM
import hashlib
import json
import os

TEXTCMDS_PATH = "/cowrie/cowrie-git/share/cowrie/txtcmds"

CACHE_PATH = "/cowrie/cowrie-git/src/model/static_setup/static_cache.json"
with open(CACHE_PATH) as cache_file:
    static_cache = json.load(cache_file)

PROFILE_PATH = "/cowrie/cowrie-git/src/model/prompts/profile.txt"
with open(PROFILE_PATH) as profile_file:
    profile = profile_file.read()
profile_bare = "".join(filter(str.isalpha, profile.lower()))
profile_hash = hashlib.sha256(profile_bare.encode("utf-8")).hexdigest()

#If not using LLM set to fake one, otherwise leave none and instantiate real one if necessary
if os.environ["COWRIE_USE_LLM"].lower() == "true":
    llm = None
else:
    llm = FakeLLM()


#build for lscpu
try:
    lscpu_resp = static_cache[profile_hash]["lscpu"]
except KeyError:
    if llm is None:
        llm = LLM()
    lscpu_resp = llm.generate_lscpu_response()

LSCPU_PATH = TEXTCMDS_PATH+"/usr/bin/lscpu"
with open(LSCPU_PATH, "w") as lscpu_file:
    lscpu_file.write(lscpu_resp)









