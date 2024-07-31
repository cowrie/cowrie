#!/usr/bin/env python
# coding: utf-8

# /*
# ! pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
# ! pip install transformers
# ! pip install datasets
# ! pip install accelerate -U
# ! pip install evaluate
# ! pip install scikit-learn
# ! pip install huggingface-hub
# */

# In[4]:


import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline


# In[5]:


### Phi-3 Mini Instruct 128k

model_ref = "microsoft/Phi-3-mini-4k-instruct"

model = AutoModelForCausalLM.from_pretrained(
model_ref, 
device_map="cuda", 
torch_dtype="auto", 
trust_remote_code=True, 
)

tokenizer = AutoTokenizer.from_pretrained(model_ref)
    
pipe = pipeline(
"text-generation",
model=model,
tokenizer=tokenizer,
)

generation_args = {
"max_new_tokens": 100,
"return_full_text": False,
"temperature": 0.2,
"do_sample": True,
}


# In[6]:


system = "You are linux server "
user = "Return the console output only for the unix command ls. Do not return code. Do not provide explanation.  "

role_system_content = "{" + "'role': 'system', 'content': '{0}'".format(system) + "}"
role_user_content = "{" + "'role': 'user', 'content': '{0}'".format(user) + "}"

messages =[role_system_content, role_user_content]

output = pipe(messages, **generation_args)
print(output)


# In[ ]:




