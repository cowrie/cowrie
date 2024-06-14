'''
from transformers import AutoModelForCausalLM, AutoTokenizer

token = open("token.txt", "r").read()

# using a simpler model for testing purpose
#model_name = "google/codegemma-7b-it"
model_name = "prajjwal1/bert-tiny"

tokenizer = AutoTokenizer.from_pretrained(model_name, token=token)
model = AutoModelForCausalLM.from_pretrained(model_name, token=token, device_map="auto", load_in_4bit=True)
'''
from transformers import AutoTokenizer, AutoModelForCausalLM

class LLM:
    def __init__(self, model_name="distilgpt2"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name)

    def generate_response(self, cmd):
        inputs = self.tokenizer(cmd, return_tensors="pt")
        output = self.model.generate(**inputs, max_new_tokens=60)
        response = self.tokenizer.decode(output[0], skip_special_tokens=True)
        return response

cowrie_llm = LLM()