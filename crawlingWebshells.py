import requests, os, sys, re
from bs4 import BeautifulSoup
from pathlib import Path
from zipfile import ZipFile, BadZipFile


url = "https://www.malware-traffic-analysis.net/2024/"

headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "text/html; charset=utf-8"}

res = requests.get(url, headers=headers)
soup = BeautifulSoup(res.text, "html.parser")
tags = soup.select("#main_content > div.blog_entry > ul > li > a.main_menu")

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

    try:
        with ZipFile(file_path, "r") as zip_ref:
            pw_prefix = "infected_" + file_path[9:19].replace("-", "")
            zip_ref.setpassword(pw_prefix.encode())
            zip_ref.extractall(malwares_dir)
    except RuntimeError as e:
        print(f"Error caused in ZIP file: `{filename}` ---------- {e}", file=sys.stderr)

    os.remove(file_path)
