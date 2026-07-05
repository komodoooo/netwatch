import os, signal
from time import sleep
from json import loads, dumps
from pymongo import MongoClient
from netrunner import NetRunner
from multiprocessing import Process

def add_results(data:dict, name:str)->bool:
    with MongoClient(os.getenv("MONGO_URI")) as client:      # re-create new istance each iteration to avoid deadlocks
        db = client["netwatch"]
        if name not in db.list_collection_names():           # to avoid errors (e.g. i delete a subnet but it's still scanning -> time key error)
            return
        pk = list(data.keys())[0]
        collection = db[name]
        host_data = loads(dumps(data[pk]))
        existing_host = collection.find_one({"hosts._id": pk})
        if existing_host:
            collection.update_one(
                {"hosts._id": pk},
                {"$set": {"hosts.$": {"_id": pk, **host_data}}}
            )
        else:
            collection.update_one(
                {},
                {"$addToSet": {"hosts": {"_id": pk, **host_data}}},  
                upsert=True
            )
        #client.close()
    print(f"INFO: {pk} scan completed")

def scan():
    queue = []
    with MongoClient(os.getenv("MONGO_URI")) as client:
        db = client["netwatch"]
        collections = db.list_collection_names()
        for i in collections:
            doc = db[i].find_one({},{"_id":0, "time":1})
            if not doc or "time" not in doc:
                continue
            queue.append((i, doc["time"]))
        #client.close()
    queue.sort(key=lambda x: x[1], reverse=True)
    for i in queue:
        print(f"INFO: Scanning {i[0]}")
        with open("/tmp/nwrst", "r+b") as f:
            f.seek(1)
            f.write(i[0].encode("utf-8"))
            f.truncate()
        NetRunner(i[0], add_results).scan()

while True:
    with MongoClient(os.getenv("MONGO_URI")) as client:
        if not client["netwatch"].list_collection_names():
            sleep(0.5)
            continue                                         # avoid spawn-terminate process loop to consume less resources in an empty config
        #client.close()
    p = Process(target=scan)
    p.start()
    while p.is_alive():
        with open("/tmp/nwrst", "rb") as flag:
            flag.seek(0)
            if b"1" in flag.read(1):
                print("WARNING: SCAN ABORTED ON REQUEST, RESTARTING...")
                with open("/tmp/nwrst", "r+b") as f:
                    f.seek(0)
                    f.write(b"0")
                os.kill(p.pid, signal.SIGKILL)
                break