import os

class CowrieHandler():
    def __init__(self, fs) -> None:
        self.fs = fs
    
    def enforce_ls(self, path: str, ls_view: str):
        items = ls_view.split(" ") 

        def is_file(item: str):
            return "." in item
        
        for item in items:
            item_path = path+"/"+item
            if not self.fs.exists(item_path):
                if is_file(item):
                    with open(item_path, "w") as file:
                        pass
                else:
                    self.fs.mkdir(item_path, 0, 0, 4096, 33188)






