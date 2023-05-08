import os
import sys
from pathlib import Path

if len(sys.argv) < 1:
    print("USAGE: python3 aflpp_dict2file_to_dir.py <DICT2FILE>")

data = open(sys.argv[1]).read().split('\n')
data = set(bytes(line[1:-1], 'utf-8') for line in data if len(line) > 0)

dict_path = Path("./dict")

if not dict_path.exists():
    Path.mkdir(dict_path)

for (index, line) in enumerate(data):
    with open(dict_path / str(index), 'wb') as f:
        f.write(line)


print(f"Writing {len(data)} elements to {dict_path}")
