import toon
import pandas as pd
import streamlit as st
import streamlit_nested_layout
import requests, bcrypt, json, io, time
from urllib.parse import quote
from gemiwrap import GeminiChat
from markdown_pdf import MarkdownPdf, Section
from streamlit_autorefresh import st_autorefresh
from ipaddress import IPv4Network, IPv6Network, ip_network

API_URL = "http://localhost:8504"
readfile = lambda p:open(p,"r").read()
def valid_subnet(sb:str)->bool:
    try:
        IPv4Network(sb, strict=False)
    except ValueError:
        try:
            IPv6Network(sb, strict=False)
        except ValueError:
            return False
    return True

def count_hosts(sb:list)->int:
    n = 0
    for i in sb:
        n+=ip_network(i, strict=False).num_addresses
    return n

def generate_ai_report(host_data:str, prompt="static/report.txt"):
    llm = GeminiChat(api_key=readfile("/opt/netwatch/creds").splitlines()[-1])
    report = llm.message(readfile(prompt)+toon.encode(host_data))
    pdf = MarkdownPdf(toc_level=2, optimize=True)
    pdf.add_section(Section("# ![](static/img/icon.png)\n\n# Netwatch AI Report\n"+report.replace('\\n','\n'), toc=True))
    buffer = io.BytesIO()
    pdf.save(buffer)
    buffer.seek(0)
    return buffer.read()

load_css = lambda name: st.markdown(f"<style>{open('static/css/'+name+'.css', 'r').read()}</style>", unsafe_allow_html=True)
st.set_page_config(page_title="Netwatch", layout="centered", page_icon="static/img/icon.png")
load_css("init")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.query_params["page"] = "login"

def login_page():
    with st.columns(3)[1]:
        st.image("static/img/logo.png", width=300)
    with st.form(key="login_form", border=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.form_submit_button("Login"):
            if bcrypt.checkpw(f"{username}:{password}".encode(), readfile("/opt/netwatch/creds").splitlines()[0].strip().encode()):
                st.session_state.logged_in = True
                st.query_params["page"] = "main"
                st.rerun()
            else:
                st.error("Wrong credentials")

def main_page():
    load_css("menu")
    with st.columns(3)[1]:
        st.markdown("# ‎ ‎Get Started")
        st.markdown("____")
        if st.button("Search"):
            st.query_params["page"] = "search"
            st.rerun()
        if st.button("Manage config"):
            st.query_params["page"] = "config"
            st.rerun()
        if st.button("Metrics"): 
            st.query_params["page"] = "metrics"
            st.rerun()
        st.markdown("____")
        if st.button("Logout"):
            st.query_params["page"] = "login"
            st.rerun()

def subnet_page():
    load_css("sbconf")
    st.markdown("# Manage configuration")
    st.subheader("Subnet list")
    sblist = pd.DataFrame(json.loads(requests.get(f"{API_URL}/subnets").text)["monitored_subnets"])
    sblist.index+=1
    current_scan = json.loads(requests.get(f"{API_URL}/ongoing_scan").text)["status"]
    try:
        ongoing_idx = sblist.index[sblist["Subnet"] == current_scan]
        if not ongoing_idx.empty:
            scan_pos = ongoing_idx[0]
            def status_label(idx):
                if idx < scan_pos:
                    return "_Queued_"
                elif idx == scan_pos:
                    return f"_**Scanning**_"
                else:
                    return "_Waiting_"
            sblist['Status'] = [status_label(idx) for idx in sblist.index]
        else:
            sblist['Status'] = "Queued"
    except KeyError: 
        pass
    st.table(sblist)
    sblist = sblist.to_dict(orient="records")
    st.subheader("Add subnet")
    new_subnet = st.text_input("New subnet with CIDR notation (e.g., 192.168.1.0/24)").strip()
    c = st.columns(4)
    with c[0]:
        if st.button("Add to list"):
            if new_subnet:
                existing_subnets = [s["Subnet"] for s in sblist]
                if new_subnet in existing_subnets:
                    st.error("Already submitted")
                elif not valid_subnet(new_subnet):
                    st.error("Invalid format")
                else:
                    requests.post(f"{API_URL}/add_subnet", json={"address":new_subnet})
                    st.rerun()
    with c[3]:
        if st.button("Restart scan"):
            if not requests.post(f"{API_URL}/restart_scan").ok:
                st.error("Error")
    st.subheader("Delete subnet")
    subnet_to_delete = st.selectbox("Select a subnet", [s["Subnet"] for s in sblist], index=None)
    c = st.columns(4)
    with c[0]:
        if st.button("Delete"):
            requests.delete(f"{API_URL}/delete_subnet", json={"address":subnet_to_delete})
            st.rerun()
    with c[3]:
        if st.button("Back"):
            st.query_params["page"] = "main"
            st.rerun()
    st_autorefresh(interval=800, key="refresh")

def search_page():
    load_css("search")
    with st.form(key="search_form", border=False):
        st.title("Search page")
        query = st.text_input("Enter your keywords")
        c = st.columns([10, 5.5, 1, 1])
        with c[0]:
            search = st.form_submit_button("Search")
        with c[3]:
            back = st.form_submit_button("Back")
    if search and query:
        st.session_state.page = 1
        st.session_state["search"] = search
        st.session_state["query"] = query
    if st.session_state.get("search") and st.session_state.get("query"):
        matched_results = json.loads(requests.get(f"{API_URL}/search?query={quote(query)}").text)["matches"]
        page_size = 16
        total_pages = (len(matched_results)-1)//page_size+1
        if matched_results:
            start = (st.session_state.page-1)*page_size
            end = start+page_size
            for result in matched_results[start:end]:
                with st.expander(f"**Results for {result['host']} ({result['subnet']})**"):
                    scanstats = result["details"]["scanstats"]
                    st.write(f"Last updated on {scanstats['timestr']}")
                    ports_cleaned = []
                    ai_report = True
                    try:
                        for p, info in result["details"]["tcp_open"].items():
                            info_copy = info.copy()
                            if "script" in info_copy:
                                info_copy["script"] = info_copy["script"].copy()
                                info_copy["script"].pop("vulners", None) 
                            ports_cleaned.append({"port": p, **info_copy})
                        if ports_cleaned:
                            st.dataframe(pd.DataFrame(ports_cleaned), hide_index=True)
                        for port, info in result["details"]["tcp_open"].items():
                            if "script" in info and "vulners" in info["script"]:
                                vulners = info["script"]["vulners"]
                                if vulners:
                                    with st.expander(f"Vulnerabilities found for {info.get('product', 'Unknown')} running on port {port}"):
                                        st.write(vulners.split(" "*4)[0].strip()[:-1])
                                        owo, uwu, ewe = [],[],[]
                                        vulners+="\n    \t.\t.\t.\t.\n"
                                        for i in vulners.replace(vulners.split(" "*4)[0],"").strip().split("\t"):
                                            if "*EXPLOIT*" in i:
                                                uwu.append(True)
                                            else:
                                                uwu.append(i)
                                            if i[-4:]==" "*4:
                                                if len(uwu)==3:
                                                    uwu.append(False)
                                                owo.append(uwu)
                                                uwu = []
                                        for i in owo:
                                            ewe.append({"ID":i[0], "URL":i[2], "CVSS":i[1], "Exploit": i[3]})
                                        st.dataframe(ewe, column_config={"URL": st.column_config.LinkColumn(label="URL" ,display_text="Open link")}, hide_index=True)
                    except KeyError:
                        st.write("**Host is up, but no TCP ports were found open during the scan.**")
                        ai_report = False
                    if "host_scripts" in result["details"]:
                        with st.expander(f"See auxiliary scripts results for {result['host']}"):
                            host_scripts_data = []
                            for script in result["details"]["host_scripts"]:
                                script_data = {
                                    'ID': script.get('id', 'Not available'),
                                    'Output': script.get('output', 'Not available')
                                }
                                host_scripts_data.append(script_data)
                            st.dataframe(pd.DataFrame(host_scripts_data), hide_index=True)
                    if ai_report and st.button("Generate AI report", key=result["host"]+result["subnet"]):
                        with st.spinner("Loading..."):
                            pdf=generate_ai_report(host_data=str(result))
                        st.write("**Warning**: AI-generated content may contain inaccuracies, consider review and verify the information independently.")
                        st.download_button(
                            label="Download PDF",
                            data=pdf,
                            file_name="report.pdf",
                            mime="application/pdf",
                        )
            #st.session_state.page = st.number_input("Page", min_value=1, value=st.session_state.page, max_value=total_pages, step=1)
            #with st.columns(3)[2]:
            #    st.number_input("Page", min_value=1, max_value=total_pages, key="page")
            c = st.columns([8.4, 9, 1])
            with c[0]:
                if st.button("Prev", disabled=st.session_state.page <= 1):
                    st.session_state.page -= 1
                    st.rerun()
            with c[1]:
                st.write(f"Page {st.session_state.page} out of {total_pages}")
            with c[2]:
                if st.button("Next", disabled=st.session_state.page >= total_pages):
                    st.session_state.page += 1
                    st.rerun()
        else:
            st.warning("No results found")
    if back:
        st.query_params["page"] = "main"
        st.rerun()

def metrics():
    st.title("Metrics")
    st.markdown("### Top Ports and Protocols")
    with st.expander("Most used services leaderboard"):
        tops=json.loads(requests.get(f"{API_URL}/top_services").text)["top_services"]
        formatted = []
        for i in tops:
            formatted.append({"Port": i.split(";")[0], "Protocol":i.split(";")[1], "Count":i.split(";")[2]})
        formatted = pd.DataFrame(formatted)
        formatted.index+=1
        st.table(formatted)
    st.markdown("### Vulnerable Software")
    with st.expander("Is strongly suggested to **update** the following software"):
        problems = []
        for i in json.loads(requests.get(f"{API_URL}/problems").text)["vulnerable_services"]:
            problems.append({"Product":i.split(";")[0], "Running on":i.split(";")[1]})
        st.dataframe(problems, hide_index=True)
    c = st.columns([6.9,1,1,1])
    with c[0]:
        b = []
        a = json.loads(requests.get(f"{API_URL}/subnets").text)["monitored_subnets"]
        for i in a:
            b.append(i["Subnet"])
        st.markdown(f"Currently Monitoring {count_hosts(b)} IP addresses.")
    with c[3]:
        if st.button("Back"):
            st.query_params["page"] = "main"
            st.rerun()

pages = {
    "login": login_page,
    "main": main_page,
    "search": search_page,
    "metrics": metrics,
    "config": subnet_page
}
page = st.query_params["page"]
if page != "search" and st.session_state.get("search") and st.session_state.get("query"):
    del st.session_state["search"]
    del st.session_state["query"]
if page in list(pages.keys()):
    pages[page]()
else:
    login_page()

@st.fragment(run_every="1s")
def page_check():
    if page != st.query_params["page"]:
        st.rerun()
page_check()