import os
from huggingface_hub import snapshot_download
if os.environ["COWRIE_USE_LLM"].lower() == "true":
    from transformers import AutoTokenizer, AutoModelForCausalLM

RESPONSE_PATH = "/cowrie/cowrie-git/src/model"

def download_model(model_path, model_name):
    """Download a Hugging Face model and tokenizer to the specified directory"""
    with open(f"{RESPONSE_PATH}/token.txt", "r") as f:
        token = f.read().rstrip()
    
    '''
    if not os.path.exists(model_path):
        os.umask(0)
        os.makedirs(model_path, mode=0o777)

    tokenizer = AutoTokenizer.from_pretrained(model_name, token=token)
    model = AutoModelForCausalLM.from_pretrained(model_name, token=token)

    model.save_pretrained(model_path+model_name)
    tokenizer.save_pretrained(model_path+model_name)
    '''

    snapshot_download(repo_id=model_name, token=token)

if os.environ["COWRIE_USE_LLM"].lower() == "true":
    download_model("models/", "microsoft/Phi-3-mini-4k-instruct")