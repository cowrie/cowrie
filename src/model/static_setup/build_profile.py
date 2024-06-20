import sys
sys.path.append("/cowrie/cowrie-git/src")

from model.llm import LLM
import hashlib
import json
import re

TEXTCMDS_PATH = "/cowrie/cowrie-git/share/cowrie/txtcmds"

CACHE_PATH = "/cowrie/cowrie-git/src/model/static_setup/static_cache.json"
with open(CACHE_PATH) as cache_file:
    static_cache = json.load(cache_file)

PROFILE_PATH = "/cowrie/cowrie-git/src/model/prompts/profile.txt"
with open(PROFILE_PATH) as profile_file:
    profile = profile_file.read()
profile_bare = "".join(filter(str.isalpha, profile.lower()))
profile_hash = hashlib.sha256(profile_bare.encode("utf-8")).hexdigest()

llm = None

#build for lscpu
try:
    lscpu_resp = static_cache[profile_hash]["lscpu"]
except KeyError:
    if llm is None:
        pass
        #llm = LLM()
    #lscpu_resp = llm.generate_lscpu_response()
    lscpu_resp = "temp while llm being fixed"

LSCPU_PATH = TEXTCMDS_PATH+"/usr/bin/lscpu"
with open(LSCPU_PATH, "w") as lscpu_file:
    lscpu_file.write(lscpu_resp)









