from pydantic import BaseModel, field_validator
from ipaddress import IPv4Network, IPv6Network
from fastapi import FastAPI, HTTPException
from collections import defaultdict
from urllib.parse import unquote
import motor.motor_asyncio
from os import getenv
from time import time

nokeys = lambda d, *keys: {k: v for k, v in d.items() if k not in keys}
client = motor.motor_asyncio.AsyncIOMotorClient(getenv("MONGO_URI"))
db = client["netwatch"]
app = FastAPI()

class Subnet(BaseModel):       # { "address": "" }
    address:str
    @field_validator("address")
    def validate_subnet(cls, v):
        try:
            IPv4Network(v, strict=False)
        except ValueError:
            try:
                IPv6Network(v, strict=False)
            except ValueError:
                raise ValueError
        return v

@app.post('/add_subnet')
async def add_subnet(subnet:Subnet):
    new_subnet = subnet.address
    if not new_subnet:
        raise HTTPException(status_code=400, detail="Required field missing")
    await db[new_subnet].insert_one({"_id": new_subnet, "time":int(time()), "hosts": []})
    return {"message": "Successfully added"}

@app.delete('/delete_subnet')
async def delete_subnet(subnet:Subnet):
    subnet_name = subnet.address
    if not subnet_name:
        raise HTTPException(status_code=400, detail="Required field missing")
    if subnet_name in await db.list_collection_names():
        await db.drop_collection(subnet_name)
        with open("/tmp/nwrst", "rb") as f1:
            f1.seek(1)
            if f1.read().decode() == subnet_name:
                with open("/tmp/nwrst", "r+b") as f2:
                    f2.seek(0)
                    f2.write(b"1")
        return {"message": "Successfully deleted"}
    else:
        raise HTTPException(status_code=404, detail="Subnet not found")

@app.get("/search")
async def search(query:str):
    try:
        keywords = unquote(query).split()
        collections = await db.list_collection_names()
        results = []
        for subnet in collections:
            async for doc in db[subnet].find():
                for host in doc.get("hosts", []):
                    elena = [keyword.lower() in str(host).lower() for keyword in keywords]
                    if sum(elena) == len(elena):
                        results.append({
                            "subnet": subnet,
                            "host": host["_id"],
                            "details": nokeys(host, "_id")
                        })
        return {"query": query, "matches": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/top_services")
async def top_services():
    port_stats = defaultdict(lambda: {"count": 0, "name": set()})
    collections = await db.list_collection_names()
    for name in collections:
        async for doc in db[name].find():
            for host in doc.get("hosts", []):
                for port, info in host.get("tcp_open", {}).items():
                    port_stats[port]["count"] += 1
                    if "name" in info:
                        port_stats[port]["name"].add(info["name"])
    results = []
    for port, data in port_stats.items():
        results.append(f"{port};{data['name'].pop().upper()};{data['count']}")
    results.sort(key=lambda x: int(x.split(";")[-1]), reverse=True)
    return {"top_services": results}

@app.get("/problems")
async def problems():
    results = []
    collections = await db.list_collection_names()
    for coll_name in collections:
        async for doc in db[coll_name].find({}, {"hosts": 1}):
            for host in doc.get("hosts", []):
                for port, info in host.get("tcp_open", {}).items():
                    if "vulners" in info.get("script", {}):
                        results.append(f"{info.get('product')} {info.get('version')};{host.get('_id')}:{port}")
    return {"vulnerable_services": results}

@app.get("/subnets")
async def subnets():
    nets = []
    names = await db.list_collection_names()
    for i in names:
        time = await db[i].find_one({},{"_id":0, "time":1})
        nets.append({"Subnet": i, "Time": time["time"]})
    nets = sorted(nets, key=lambda x: x["Time"], reverse=True)
    for i in nets:
        i.pop("Time", None)
    return {"monitored_subnets": nets}

@app.post("/restart_scan")
async def restart_scan():
    with open("/tmp/nwrst", "r+b") as f:
        f.seek(0)
        f.write(b"1")
    return {"status":"restarted"}

@app.get("/ongoing_scan")
async def ongoing_scan():
    with open("/tmp/nwrst", "rb") as f:
        f.seek(1)
        return {"status": f.read().decode()}