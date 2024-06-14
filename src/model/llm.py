from transformers import AutoTokenizer, AutoModelForCausalLM

class LLM:
    def __init__(self, model_name="google/codegemma-2b"):
        token = open("token.txt", "r").read()
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, token=token)
        self.model = AutoModelForCausalLM.from_pretrained(model_name, token=token, device_map="auto")

    def generate_response(self, cmd):
        base_prompt = "You are Linux OS terminal for a server containing sensitive patient data. "+\
            "Your personality is: You are a Linux OS terminal. You act and respond exactly as a Linux terminal. "+\
            "You will respond to all commands just as a Linux terminal would. " +\
            "You can only respond to user inputs and you must not write any commands on your own. " +\
            "You must not in any case have a conversation with user as a chatbot and must not explain your output and do not repeat commands user inputs. " +\
            "Do not explain to user what they are seeing. Only respond as Linux terminal. "+\
            "You will need to make up realistic answers to the command, as they would be returned by a real linux terminal for a hospital server. "+\
            "It is very important that you do not name files and directiories file1.txt file2.txt file3.txt or similarly, rather create plausible file names for a real terminal with patient data.\n\n"+\
            "pwd"
        answer1 = "/home/admin"
        prompt2 = cmd 
        messages = [{"role": "user", "content": base_prompt},
                    {"role": "assistant", "content": answer1},
                    {"role": "user", "content": prompt2}]

        tokenized_chat = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors="pt")
        len_chat = tokenized_chat.shape[1]
        outputs = self.model.generate(tokenized_chat, max_new_tokens=100)
        response = self.tokenizer.decode(outputs[0][len_chat:], skip_special_tokens=True)
        return response

cowrie_llm = LLM()