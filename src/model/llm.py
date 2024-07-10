import os
#To be added for LLM
if os.environ["COWRIE_USE_LLM"].lower() == "true":
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, StoppingCriteria, StoppingCriteriaList
    import torch
import re
import json

RESPONSE_PATH = "/cowrie/cowrie-git/src/model"
PROMPTS_PATH = "/cowrie/cowrie-git/src/model/prompts"

TEMPLATE_TOKEN = "<unk>"
TEMPLATE_TOKEN_ID = 0
SYSTEM_ROLE_AVAILABLE = True


with open(f"{RESPONSE_PATH}/cmd_lookup.json", "r") as f:
    LOOKUPS = json.load(f)

class LLM:
    def __init__(self, model_name="microsoft/Phi-3-mini-4k-instruct"):
        with open(f"{RESPONSE_PATH}/token.txt", "r") as f:
            token = f.read().rstrip()

        self.profile = self.get_profile()

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")

        quantization_config = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16)
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, token=token)
        self.model = AutoModelForCausalLM.from_pretrained(model_name, token=token, device_map="auto", quantization_config=quantization_config)

    def get_profile(self):
        with open(PROMPTS_PATH+"/profile.txt", "r") as prompt_file:
            profile = prompt_file.read()
        return profile

    def get_examples(self, cmd):
        with open(PROMPTS_PATH+f"/ex_{cmd}.json", "r") as ex_file:
            examples = json.load(ex_file)
        return examples


    def generate_from_messages(self, messages, max_new_tokens=100):
        tokenized_chat = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt")
        print("tokenized chat:")
        print(tokenized_chat)
        len_chat = tokenized_chat.shape[1]
        outputs = self.model.generate(tokenized_chat, max_new_tokens=max_new_tokens)
        response = self.tokenizer.decode(outputs[0][len_chat:], skip_special_tokens=True)
        return response

    def generate_ls_response(self, cwd):
        def format_q(cmd, cwd):
            return f"Command: {cmd}\nCurrent directory: {cwd}"

        #Maybe we should load all these by initialisation
        examples = self.get_examples("ls")
        ex_q = [format_q(ex["cmd"], ex["cwd"]) for ex in examples]
        ex_a = [ex["response"] for ex in examples]

        messages = [{"role":"user", "content":self.profile},
                    {"role":"model", "content":""}]
        for i in range(len(examples)):
            messages.append({"role":"user", "content":ex_q[i]})
            messages.append({"role":"model", "content":ex_a[i]})
        
        messages.append({"role":"user", "content":format_q("ls", cwd)})

        return self.generate_from_messages(messages)


    def fill_template(self, messages, max_slot_len=20):
        tokenized_template = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=False, return_tensors="pt")
        
        holes = tokenized_template == TEMPLATE_TOKEN_ID
        hole_indices = holes.nonzero()[:,1]

        stopping_criteria = StoppingCriteriaList([NewWordSC(tokenizer=self.tokenizer)])

        before = tokenized_template[:, :hole_indices[0]]  
        for i in range(hole_indices.shape[0]):
            hole_i = hole_indices[i]
    
            #Need to check for cutoff instead of just removing last token if we want sampling
            before = self.model.generate(before, 
                                         do_sample=False,
                                         max_new_tokens=max_slot_len,
                                         stopping_criteria=stopping_criteria,
                                         bad_words_ids=[[TEMPLATE_TOKEN_ID]])[:, :-1]
            if hole_i == hole_indices[-1]:
              tokenized_template = torch.cat([before, tokenized_template[:, hole_i+1:]], dim=1)
            else:
              before = torch.cat([before, tokenized_template[:, hole_i+1:hole_indices[i+1]]], dim=1)
        return self.tokenizer.decode(tokenized_template[0, :])




    def generate_ifconfig_response_template(self, messages):
        template = f"""
eth0      Link encap:Ethernet  HWaddr {TEMPLATE_TOKEN}  
          inet addr:{TEMPLATE_TOKEN}  Bcast:{TEMPLATE_TOKEN}  Mask:{TEMPLATE_TOKEN}
          inet6 addr: {TEMPLATE_TOKEN} Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:123456 errors:0 dropped:0 overruns:0 frame:0
          TX packets:123456 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:{TEMPLATE_TOKEN} ({TEMPLATE_TOKEN} MB)  TX bytes:{TEMPLATE_TOKEN} ({TEMPLATE_TOKEN} MB)
          Interrupt:20 Memory:fa800000-fa820000 

lo        Link encap:Local Loopback  
          inet addr:{TEMPLATE_TOKEN}  Mask:{TEMPLATE_TOKEN}
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:{TEMPLATE_TOKEN}  Metric:1
          RX packets:1234 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1234 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:{TEMPLATE_TOKEN} ({TEMPLATE_TOKEN} KB)  TX bytes:{TEMPLATE_TOKEN} ({TEMPLATE_TOKEN} KB)
"""

        messages.append({"role":"model", "content":template})
        return self.fill_template(messages)


    def generate_ifconfig_response(self, use_template=True):
        base_prompt = self.profile
        examples = self.get_examples("ifconfig")

        if len(examples) > 0:
            base_prompt = base_prompt + f'\n\nHere {"are a few examples" if len(examples) > 1 else "is an example"} of a response to the ifconfig command:'
            for i in range(len(examples)):
                base_prompt = base_prompt+f"\n\nExample {i+1}:\n"+examples[i]["response"]

        if SYSTEM_ROLE_AVAILABLE:
            messages = [
                {"role":"system", "content":base_prompt}
                ]
        else:
            messages = [
                {"role":"user", "content":base_prompt},
                {"role":"model", "content":""}
                ]
        messages.append({"role":"user", "content":"COMMAND: ifconfig"})

        if use_template:
            return self.generate_ifconfig_response_template(messages)
        return self.generate_from_messages(messages, max_new_tokens=1000)

    def generate_lscpu_response(self):
        profile = self.get_profile()

        return "Makeshift lscpu response"
    
class FakeLLM:
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, attr):
        def func(*args, **kwargs):
            return "Something generated by a LLM"
        return func
    

class NewWordSC(StoppingCriteria):
    def __init__(self, tokenizer):
        super().__init__()
        self.tokenizer = tokenizer
    
    def __call__(self, input_ids: torch.LongTensor, scores: torch.FloatTensor):
        lasts = input_ids[:, -1]
        res = torch.zeros_like(lasts, dtype=torch.bool)
        for i in range(lasts.shape[0]):
            decoded = self.tokenizer.decode(lasts[i])
            #print(f"decoded: '{decoded}'")
            if " " in decoded:
                res[i] = True
            elif "\n" in decoded:
                res[i] = True
            elif "\t" in decoded:
                res[i] = True
            elif decoded == "":
              res[i] = True
        return res