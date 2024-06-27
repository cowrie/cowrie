import os
#To be added for LLM
if os.environ["COWRIE_USE_LLM"].lower() == "true":
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, AutoConfig
    from accelerate import init_empty_weights, dispatch_model
    import torch

import json

RESPONSE_PATH = "/cowrie/cowrie-git/src/model"

PROMPTS_PATH = "/cowrie/cowrie-git/src/model/prompts"

with open(f"{RESPONSE_PATH}/cmd_lookup.json", "r") as f:
    LOOKUPS = json.load(f)

class LLM:
    def __init__(self, model_name="google/codegemma-7b-it"):
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

    def create_messages(self, base_prompt, cmd):
        answer = LOOKUPS[cmd]
        messages = [
            {"role": "user", "content": base_prompt},
            {"role": "assistant", "content": answer},
            {"role": "user", "content": cmd}
        ]
        return messages

    def generate_response(self, cmd):
        base_prompt = f"You are Linux OS terminal for a server containing sensitive patient data. "+\
            "Your personality is: You are a Linux OS terminal. You act and respond exactly as a Linux terminal. "+\
            "You will respond to all commands just as a Linux terminal would. " +\
            "You can only respond to user inputs and you must not write any commands on your own. " +\
            "You must not in any case have a conversation with user as a chatbot and must not explain your output and do not repeat commands user inputs. " +\
            "Do not explain to user what they are seeing. Only respond as Linux terminal. "+\
            "You will need to make up realistic answers to the command, as they would be returned by a real linux terminal for a hospital server. "+\
            "It is very important that you do not name files and directiories file1.txt file2.txt file3.txt or similarly, rather create plausible file names for a real terminal with patient data.\n\n"+\
            "{cmd}"
        
        if cmd == "ifconfig":
            return self.generate_ifconfig_response(base_prompt)
        else:
            messages = self.create_messages(base_prompt, cmd)
            tokenized_chat = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt").to(self.device)
            len_chat = tokenized_chat.shape[1]
            outputs = self.model.generate(tokenized_chat, max_new_tokens=500)
            response = self.tokenizer.decode(outputs[0][len_chat:], skip_special_tokens=True)
            return response
    
    def generate_dynamic_content(self, base_prompt, dynamic_part):
        messages = [
            {"role": "user", "content": base_prompt},
            {"role": "assistant", "content": dynamic_part},
        ]
        tokenized_chat = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt").to(self.device)
        len_chat = tokenized_chat.shape[1]
        outputs = self.model.generate(tokenized_chat, max_new_tokens=50)
        response = self.tokenizer.decode(outputs[0][len_chat:], skip_special_tokens=True)
        return response.strip()
    
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

    
    def generate_ifconfig_response(self, base_prompt):
        static_ifconfig_template = """
        eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
                inet {ip_address}  netmask 255.255.255.0  broadcast 192.168.1.255
                inet6 {ipv6_address}  prefixlen 64  scopeid 0x20<link>
                ether {mac_address}  txqueuelen 1000  (Ethernet)
                RX packets 123456  bytes 987654321 (987.6 MB)
                RX errors 0  dropped 0  overruns 0  frame 0
                TX packets 123456  bytes 987654321 (987.6 MB)
                TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        """

        ip_prompt = base_prompt.format(cmd="Generate a realistic IP address for a hospital server.")
        ipv6_prompt = base_prompt.format(cmd="Generate a realistic IPv6 address for a hospital server.")
        mac_prompt = base_prompt.format(cmd="Generate a realistic MAC address for a hospital server.")

        ip_address = self.generate_dynamic_content(ip_prompt, "IP Address:")
        ipv6_address = self.generate_dynamic_content(ipv6_prompt, "IPv6 Address:")
        mac_address = self.generate_dynamic_content(mac_prompt, "MAC Address:")

        ifconfig_response = static_ifconfig_template.format(
            ip_address=ip_address,
            ipv6_address=ipv6_address,
            mac_address=mac_address
        )

        return ifconfig_response

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