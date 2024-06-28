import os
#To be added for LLM
if os.environ["COWRIE_USE_LLM"].lower() == "true":
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig, AutoConfig
    from accelerate import init_empty_weights, dispatch_model
    import torch
import re
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
        print(ifconfig_response)

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