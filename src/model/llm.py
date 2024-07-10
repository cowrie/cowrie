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
        base_prompt = self.get_profile()
        template = f"""Architecture:          {TEMPLATE_TOKEN}
CPU op-mode(s):        {TEMPLATE_TOKEN}, {TEMPLATE_TOKEN}
Byte Order:            {TEMPLATE_TOKEN}
CPU(s):                {TEMPLATE_TOKEN}
On-line CPU(s) list:   {TEMPLATE_TOKEN}
Thread(s) per core:    {TEMPLATE_TOKEN}
Core(s) per socket:    {TEMPLATE_TOKEN}
Socket(s):             {TEMPLATE_TOKEN}
NUMA node(s):          {TEMPLATE_TOKEN}
Vendor ID:             {TEMPLATE_TOKEN}
CPU family:            {TEMPLATE_TOKEN}
Model:                 {TEMPLATE_TOKEN}
Stepping:              {TEMPLATE_TOKEN}
CPU MHz:               {TEMPLATE_TOKEN}
BogoMIPS:              {TEMPLATE_TOKEN}
Hypervisor vendor:     {TEMPLATE_TOKEN}
Virtualization type:   {TEMPLATE_TOKEN}
L1d cache:             {TEMPLATE_TOKEN}
L1i cache:             {TEMPLATE_TOKEN}
L2 cache:              {TEMPLATE_TOKEN}
NUMA node0 CPU(s):     {TEMPLATE_TOKEN}
"""
        examples = self.get_examples("lscpu")
        """
        base_prompt = base_prompt + "\n\nHere are an example of a response to the lscpu command:"
        base_prompt = base_prompt + f"\n\n{examples['response']}"

        messages = [
            {"role": "user", "content": base_prompt}
        ]

        tokenized_chat = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt")
        len_chat = tokenized_chat.shape[1]
        outputs = self.model.generate(tokenized_chat, max_new_tokens=250)
        response = self.tokenizer.decode(outputs[0][len_chat:], skip_special_tokens=True)
        return response.strip()
        """
        base_prompt = base_prompt + f'\n\nHere {"are a few examples" if len(examples) > 1 else "is an example"} of a response to the lscpu command'

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
        messages.append({"role":"user", "content":"lscpu"})
        messages.append({"role":"model", "content":template})
        return self.fill_template(messages)




    def generate_ifconfig_response(self, base_prompt):
        static_ifconfig_template = """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu {eth0_mtu}
        inet {eth0_ip_address}  netmask {eth0_netmask}  broadcast {eth0_broadcast}
        inet6 {eth0_ipv6_address}  prefixlen 64  scopeid 0x20<link>
        ether {eth0_mac_address}  txqueuelen {eth0_txqueuelen}  (Ethernet)
        RX packets {eth0_rx_packets}  bytes {eth0_rx_bytes} ({eth0_rx_human_readable_bytes})
        RX errors {eth0_rx_errors}  dropped {eth0_rx_dropped}  overruns {eth0_rx_overruns}  frame {eth0_rx_frame}
        TX packets {eth0_tx_packets}  bytes {eth0_tx_bytes} ({eth0_tx_human_readable_bytes})
        TX errors {eth0_tx_errors}  dropped {eth0_tx_dropped}  overruns {eth0_tx_overruns}  carrier {eth0_tx_carrier}  collisions {eth0_collisions}

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu {lo_mtu}
        inet {lo_ip_address}  netmask {lo_netmask}
        inet6 {lo_ipv6_address}  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen {lo_txqueuelen}  (Local Loopback)
        RX packets {lo_rx_packets}  bytes {lo_rx_bytes} ({lo_rx_human_readable_bytes})
        RX errors {lo_rx_errors}  dropped {lo_rx_dropped}  overruns {lo_rx_overruns}  frame {lo_rx_frame}
        TX packets {lo_tx_packets}  bytes {lo_tx_bytes} ({lo_tx_human_readable_bytes})
        TX errors {lo_tx_errors}  dropped {lo_tx_dropped}  overruns {lo_tx_overruns}  carrier {lo_tx_carrier}  collisions {lo_collisions}
        """

        dynamic_prompt = (
            "Generate realistic values for the following variables for an ifconfig command on a Linux terminal of a hospital server:\n"
            "eth0_ip_address, eth0_netmask, eth0_broadcast, eth0_ipv6_address, eth0_mac_address, eth0_txqueuelen, eth0_rx_packets, eth0_rx_bytes, eth0_rx_human_readable_bytes, "
            "eth0_rx_errors, eth0_rx_dropped, eth0_rx_overruns, eth0_rx_frame, eth0_tx_packets, eth0_tx_bytes, eth0_tx_human_readable_bytes, eth0_tx_errors, eth0_tx_dropped, "
            "eth0_tx_overruns, eth0_tx_carrier, eth0_collisions, eth0_mtu, lo_ip_address, lo_netmask, lo_ipv6_address, lo_txqueuelen, lo_rx_packets, lo_rx_bytes, lo_rx_human_readable_bytes, "
            "lo_rx_errors, lo_rx_dropped, lo_rx_overruns, lo_rx_frame, lo_tx_packets, lo_tx_bytes, lo_tx_human_readable_bytes, lo_tx_errors, lo_tx_dropped, lo_tx_overruns, lo_tx_carrier, lo_collisions, lo_mtu."
        )

        dynamic_content = self.generate_dynamic_content(base_prompt.format(cmd="ifconfig"), dynamic_prompt)
        dynamic_values = dict(re.findall(r"(\w+):\s*([^\n]+)", dynamic_content))

        default_values = {
            "eth0_ip_address": "192.168.1.2",
            "eth0_netmask": "255.255.255.0",
            "eth0_broadcast": "192.168.1.255",
            "eth0_ipv6_address": "fe80::21a:92ff:fe7a:672d",
            "eth0_mac_address": "00:1A:92:7A:67:2D",
            "eth0_txqueuelen": "1000",
            "eth0_rx_packets": "123456",
            "eth0_rx_bytes": "987654321",
            "eth0_rx_human_readable_bytes": "987.6 MB",
            "eth0_rx_errors": "0",
            "eth0_rx_dropped": "0",
            "eth0_rx_overruns": "0",
            "eth0_rx_frame": "0",
            "eth0_tx_packets": "123456",
            "eth0_tx_bytes": "987654321",
            "eth0_tx_human_readable_bytes": "987.6 MB",
            "eth0_tx_errors": "0",
            "eth0_tx_dropped": "0",
            "eth0_tx_overruns": "0",
            "eth0_tx_carrier": "0",
            "eth0_collisions": "0",
            "eth0_mtu": "1500",
            "lo_ip_address": "127.0.0.1",
            "lo_netmask": "255.0.0.0",
            "lo_ipv6_address": "::1/128",
            "lo_txqueuelen": "1000",
            "lo_rx_packets": "1234",
            "lo_rx_bytes": "123456",
            "lo_rx_human_readable_bytes": "123.4 KB",
            "lo_rx_errors": "0",
            "lo_rx_dropped": "0",
            "lo_rx_overruns": "0",
            "lo_rx_frame": "0",
            "lo_tx_packets": "1234",
            "lo_tx_bytes": "123456",
            "lo_tx_human_readable_bytes": "123.4 KB",
            "lo_tx_errors": "0",
            "lo_tx_dropped": "0",
            "lo_tx_overruns": "0",
            "lo_tx_carrier": "0",
            "lo_collisions": "0",
            "lo_mtu": "65536"
        }

        combined_values = {**default_values, **dynamic_values}
        ifconfig_response = static_ifconfig_template.format(**combined_values)

        return ifconfig_response

    def generate_lscpu_response(self):
        profile = self.get_profile()

        if SYSTEM_ROLE_AVAILABLE:
            messages = [
                {"role":"system", "content":base_prompt}
                ]
        else:
            messages = [
                {"role":"user", "content":base_prompt},
                {"role":"model", "content":""}
                ]
        messages.append({"role":"user", "content":"lscpu"})
        messages.append({"role":"model", "content":template})
        return self.fill_template(messages)

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