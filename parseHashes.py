import re
from pathlib import Path

hashList = []
hashPattern = r"SHA256 hash: ([0-9a-fA-F]+)"

malwares_dir = Path.cwd() / "malwares"
for file_path in malwares_dir.glob("*.txt"):
    with open(file_path, "r", encoding='utf-8') as file:
        contents = file.read()
        hashes = re.findall(hashPattern, contents, re.DOTALL)
        for hash in hashes:
            hashList.append(hash)

print(hashList)
