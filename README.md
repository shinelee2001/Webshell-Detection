It utilizes sqlite3 library for C++.
It crawls webshell signatures from "https://www.malware-traffic-analysis.net/".

Further reqruied update:
  1. logging.
  2. sha256 for hashing detected webshells. (currently uses md5)
     2.1. Logic for comparing files in a given directory and signatures in DB is required.
  3. crawling signatures and directly save to the database. (currently crawls signatures and stores in output.txt then DB reads output.txt)
  4. Improve detection algorithm to look for various malicious patterns. (currently it only looks for exploitable functions)
