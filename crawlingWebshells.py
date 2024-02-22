import requests, os, sys, re
from bs4 import BeautifulSoup
from pathlib import Path
from zipfile import ZipFile, BadZipFile


url = "https://www.malware-traffic-analysis.net/2024/"

headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "text/html; charset=utf-8"}

res = requests.get(url, headers=headers)
soup = BeautifulSoup(res.text, "html.parser")
tags = soup.select("#main_content > div.blog_entry > ul > li > a.main_menu")

###################################################
## Collect the urls containing malware zip files ##
###################################################
links = []
for tag in tags:
    links.append(tag["href"])

fileUrls = []
for link in links:
    newUrl = url + link
    res = requests.get(newUrl, headers=headers)
    soup = BeautifulSoup(res.text, "html.parser")
    tags = soup.select("#main_content > div.blog_entry > ul > li:nth-child(1) > a")
    for tag in tags:
        if ".txt.zip" in tag["href"]:
            txtFile = tag["href"]
            txtFileUrl = newUrl[:-10] + txtFile
            fileUrls.append(txtFileUrl)

malwares_dir = Path("./malwares")
malwares_dir.mkdir(parents=True, exist_ok=True)

for fileUrl in fileUrls:
    res = requests.get(fileUrl, headers=headers)
    filename = os.path.basename(fileUrl)
    file_path = os.path.join(malwares_dir, filename)
    with open(file_path, "wb") as f:
        f.write(res.content)

    ###############################################
    ## Download/unzip and extract the .txt files ##
    ###############################################
    try:
        with ZipFile(file_path, "r") as zip_ref:
            pw = "infected_" + file_path[9:19].replace("-", "")
            zip_ref.setpassword(pw.encode())
            zip_ref.extractall(malwares_dir)
    except RuntimeError as e:
        print(f"Error caused in ZIP file: `{filename}` ---------- {e}", file=sys.stderr)

    # Remove .zip files after extracting .txt files
    os.remove(file_path)


#################################################################
## Colllect the hashes from .txt files and store in output.txt ##
#################################################################
hashList = []
hashPattern = r"SHA256 hash: ([0-9a-fA-F]+)"
output_path = os.path.join(malwares_dir, "output.txt")

for file_path in malwares_dir.glob("*.txt"):
    with open(file_path, "r", encoding="utf-8") as file:
        contents = file.read()
        hashes = re.findall(hashPattern, contents, re.DOTALL)
        for hash in hashes:
            try:
                with open(output_path, "a") as output:
                    output.write(str(hash) + "\n")
            except Exception as e:
                print(f"Error causes while storing the hash: {hash} ---------- {e}")
