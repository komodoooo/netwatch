import subprocess, time, os

with open("/tmp/nwrst", "wb") as f:
    f.write(b"0")

if not os.getenv("MONGO_URI"):
    os.environ["MONGO_URI"] = "mongodb://mongo:27017"

log_file = open("activity.log", "w")
log_file.write(time.strftime("%Y-%m-%d %H:%M\n"))
log_file.flush()

processes = [
    subprocess.Popen(
        ["python3", "worker.py"],
        stdout=log_file,
        stderr=log_file
    ),
    subprocess.Popen(
        "uvicorn apiserver:app --reload --host 0.0.0.0 --port 8504".split(),
        stdout=subprocess.DEVNULL,
        stderr=log_file
    ),
    subprocess.Popen(
        "streamlit run index.py --server.port=8503 --server.address=0.0.0.0 "
        "--client.toolbarMode=minimal --theme.base=dark --theme.primaryColor=aecbd3 --theme.backgroundColor=#000000".split(),
        stdout=subprocess.DEVNULL,
        stderr=log_file
    )
]

try:
    for p in processes:
        p.wait()
except Exception as e:
    for p in processes:
        p.terminate()
    log_file.write(str(e))