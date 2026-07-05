import numpy as np
import nmap, ipaddress
from multiprocessing import Manager

# nmap 1000 top ports list is very outdated, so i took them from shodan
# https://gist.github.com/komodoooo/38e1c1fc32e38eb3f0990f052538c708

TOP_PORTS = open("static/ports.txt", "r").read().splitlines()

class NetRunner:
    def __init__(self, subnet, func=None):  # custom function to save data on callback
        self.top_ports = ",".join([i for i in TOP_PORTS])
        self.subnet = subnet
        self.nma = nmap.PortScannerAsync()
        self.data = Manager().dict()
        self.uphosts = Manager().list()
        self.func = func
    def callback(self, host, result):
        result["scanstats"] = result["nmap"].pop("scanstats")
        result["nmap"].pop("scanstats", None)
        result.pop("nmap", None)
        try:
            result["tcp_open"] = result["scan"][host].pop("tcp")
        except KeyError:
            pass
        result["host_scripts"] = result["scan"][host].pop("hostscript")
        if "host_scripts" in result:
            for script in result["host_scripts"]:
                if "id" in script and script["id"] == "port-states":
                    result["host_scripts"].remove(script)
        result.pop("scan", None)
        self.clean_data()
        self.data[host] = result
        if self.func!=None: 
            self.func({host: result}, self.subnet)
    def scan(self):
        self.nma.scan(
            hosts=self.subnet,
            arguments="-sn -T4"+(" -6" if ":" in self.subnet else ""),      # Some firewalls could block ICMP, RST flag expected.
            callback=lambda h, r:self.uphosts.append(h) if r["nmap"]["scanstats"]["uphosts"] == "1" else None
        )
        while self.nma.still_scanning():
            self.nma.wait(3)
        if self.uphosts:
            self.uphosts = sorted(self.uphosts, key=ipaddress.ip_address)
            for chunk in np.array_split(np.array(self.uphosts),int(-(-len(self.uphosts)//16))):
                nm = nmap.PortScanner()                                     # Using the built-in nmap wrapper package async scanner means much less efficiency for just few results each 10 minutes or so
                nm.scan(
                    hosts=" ".join([i for i in chunk.tolist()]),    
                    arguments=f"-Pn -sS -T4 -sV --max-retries=4 --script=\"(default or safe or vuln or auth or discovery) and not "  
                        +f"{' and not '.join([i for i in open('static/nse-blacklist.txt', 'r').read().splitlines()])}\" " # exclude the most sloppy scripts, add/remove what you want
                        +f"-p{self.top_ports} --min-parallelism={len(chunk.tolist())*3}"+(" -6" if ":" in self.subnet else "")
                )
                for host in nm.all_hosts():
                    result = {
                        "nmap": { "scanstats": nm.scanstats() },
                        "scan": { host: nm[host] }
                    }
                    self.callback(host, result)
    def recursive_clean(self, data):
        keys_to_remove = ["conf", "command_line", "scaninfo", "addresses",
                        "status", "totalhosts", "elapsed", "uphosts", "downhosts"]
        for key in keys_to_remove:
            data.pop(key, None)
        for value in data.values():
            if isinstance(value, dict):
                self.recursive_clean(value)
    def clean_data(self):
        data = dict(self.data)
        for value in data.values():
            if isinstance(value, dict):
                self.recursive_clean(value)
        return data
    def acquired_data(self):
        return self.clean_data()

#import json
#runner = NetRunner(input("> "))
#runner.scan()
#results = runner.acquired_data()
#if not results: print("empty")
#open("output.json", "w").write(json.dumps(results, indent=4))