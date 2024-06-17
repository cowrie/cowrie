import random
import time

class CowrieHandler():
    def __init__(self, fs) -> None:
        self.fs = fs
    
    def enforce_ls(self, path: str, ls_view: str):
        items = ls_view.split(" ") 

        def is_file(item: str):
            return "." in item
        
        def random_time(months_ago):
            ctime = time.time()
            return ctime-random.uniform(0, months_ago*30*24*60*60)

        def random_size():
            return random.randrange(1024, int(4e6), 1024)
        
        for item in items:
            item_path = path+"/"+item
            if not self.fs.exists(item_path):
                if is_file(item):
                    self.fs.mkfile(item_path, 0, 0, random_size(), 33188, random_time(6), is_llm=True)
                else:
                    self.fs.mkdir(item_path, 0, 0, 4096, 33188, random_time(6), is_llm=True)




