import os
if os.environ["COWRIE_USE_LLM"].lower() == "true":
    from transformers import AutoTokenizer, AutoModelForCausalLM

def download_model(model_path, model_name):
    """Download a Hugging Face model and tokenizer to the specified directory"""
    token = open("/cowrie/cowrie-git/src/model/token.txt", "r").read().rstrip()
    if not os.path.exists(model_path):
        os.umask(0)
        os.makedirs(model_path, mode=0o777)

    tokenizer = AutoTokenizer.from_pretrained(model_name, token=token)
    model = AutoModelForCausalLM.from_pretrained(model_name, token=token)

    model.save_pretrained(model_path)
    tokenizer.save_pretrained(model_path)

if os.environ["COWRIE_USE_LLM"].lower() == "true":
    download_model("models/", "google/codegemma-7b-it")