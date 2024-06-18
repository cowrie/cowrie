from transformers import AutoTokenizer, AutoModelForCausalLM
import os

def download_model(model_path, model_name):
    """Download a Hugging Face model and tokenizer to the specified directory"""
    token = open("token.txt", "r").read()
    if not os.path.exists(model_path):
        os.umask(0)
        os.makedirs(model_path, mode=0o777)

    tokenizer = AutoTokenizer.from_pretrained(model_name, token=token)
    model = AutoModelForCausalLM.from_pretrained(model_name, token=token)

    model.save_pretrained(model_path)
    tokenizer.save_pretrained(model_path)

#download_model("models/", "google/codegemma-7b-it")