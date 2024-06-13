'''
from transformers import AutoModelForCausalLM, AutoTokenizer

token = open("token.txt", "r").read()

# using a simpler model for testing purpose
#model_name = "google/codegemma-7b-it"
model_name = "prajjwal1/bert-tiny"

tokenizer = AutoTokenizer.from_pretrained(model_name, token=token)
model = AutoModelForCausalLM.from_pretrained(model_name, token=token, device_map="auto", load_in_4bit=True)
'''
from transformers import GPT2LMHeadModel, GPT2Tokenizer

class LLM:
    def __init__(self, model_name="distilgpt2"):
        self.tokenizer = GPT2Tokenizer.from_pretrained(model_name)
        self.model = GPT2LMHeadModel.from_pretrained(model_name)

    def generate_response(self, cmd):
        inputs = self.tokenizer(cmd, return_tensors="pt")
        response = self.model(**inputs)
        #outputs = self.model.generate(inputs, max_length=100, num_return_sequences=1)
        #response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return response

cowrie_llm = LLM()