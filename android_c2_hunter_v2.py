#!/usr/bin/env python3
import argparse,csv,hashlib,ipaddress,json,re,shutil,socket,subprocess,time
from collections import defaultdict
from datetime import datetime,timezone
from pathlib import Path

SUSPICIOUS_PORTS={4444,5555,1337,31337,12345,6667}
COMMON_PORTS={53,80,123,443,853,5228,5229,5230,8080,8443}
STATES={"01":"ESTABLISHED","02":"SYN_SENT","03":"SYN_RECV","04":"FIN_WAIT1","05":"FIN_WAIT2","06":"TIME_WAIT","07":"CLOSE","08":"CLOSE_WAIT","09":"LAST_ACK","0A":"LISTEN","0B":"CLOSING"}

def ts(): return datetime.now(timezone.utc).isoformat()
def run(a,t=30):
    try:
        p=subprocess.run(a,text=True,capture_output=True,timeout=t)
        return p.returncode,p.stdout,p.stderr
    except Exception as e:return 1,"",str(e)
def adb(a,t=30):return run(["adb"]+a,t)
def sh(c,t=30):return adb(["shell",c],t)
def valid_ip(x):
    try:ipaddress.ip_address(x);return True
    except:return False
def priv(x):
    try:return ipaddress.ip_address(x).is_private
    except:return False
def h4(x):
    try:return socket.inet_ntoa(bytes.fromhex(x)[::-1])
    except:return None
def h6(x):
    try:return str(ipaddress.IPv6Address(bytes.fromhex(x)))
    except:return None
def parse(text,proto):
    out=[]; dec=h6 if proto.endswith("6") else h4
    for ln in text.splitlines()[1:]:
        p=ln.split()
        if len(p)<10:continue
        try:
            la,ra,st=p[1],p[2],p[3]
            lih,lp=la.rsplit(":",1); rih,rp=ra.rsplit(":",1)
            out.append({"proto":proto,"local_ip":dec(lih),"local_port":int(lp,16),"remote_ip":dec(rih),"remote_port":int(rp,16),"state_hex":st,"state":STATES.get(st,st) if proto.startswith("tcp") else "UDP","uid":p[7],"inode":p[9]})
        except:pass
    return out
def sockets():
    z=[]
    for p in ("tcp","tcp6","udp","udp6"):
        rc,o,e=sh("cat /proc/net/"+p,10)
        if rc==0:z+=parse(o,p)
    return z
def uid_packages():
    rc,o,e=sh("pm list packages -U",30); d=defaultdict(list)
    for ln in o.splitlines():
        m=re.match(r"package:(.+?) uid:(\d+)",ln.strip())
        if m:d[m.group(2)].append(m.group(1))
    return d
def pid_inodes():
    script='for p in /proc/[0-9]*; do pid=${p##*/}; for f in "$p"/fd/*; do x=$(readlink "$f" 2>/dev/null); case "$x" in socket:[[]*[]]) echo "$pid ${x#socket:[}";; esac; done; done'
    rc,o,e=sh("sh -c "+json.dumps(script),35); d=defaultdict(set)
    if rc==0:
        for ln in o.splitlines():
            m=re.match(r"^(\d+)\s+(\d+)",ln.strip())
            if m:d[m.group(2)].add(m.group(1))
    return d
def pmap():
    rc,o,e=sh("ps -A -o USER,PID,NAME 2>/dev/null || ps -A",20); d={}
    for ln in o.splitlines()[1:]:
        p=ln.split()
        if len(p)>=3 and p[1].isdigit():d[p[1]]=p[-1]
    return d
def load_iocs(path):
    if not path or not Path(path).exists():return set()
    return {x.strip().split()[0] for x in Path(path).read_text(errors="ignore").splitlines() if x.strip() and not x.lstrip().startswith("#")}
def score(r,n,iocs):
    s=0; why=[]; ip=r["remote_ip"]; port=r["remote_port"]
    if ip in iocs:s+=100;why.append("IOC_MATCH")
    if ip and not priv(ip):s+=1
    else:why.append("PRIVATE_REMOTE")
    if port in SUSPICIOUS_PORTS:s+=5;why.append("SUSPICIOUS_PORT")
    if port>1024 and port not in COMMON_PORTS:s+=2;why.append("UNCOMMON_PORT")
    if n>=10:s+=2;why.append("REPEATED_CONNECTION")
    if r["proto"].startswith("udp") and port not in {53,123,443}:s+=1;why.append("NONSTANDARD_UDP")
    return s,why
def sha(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
    return h.hexdigest()
def static(a,out,iocs):
    out.mkdir(parents=True,exist_ok=True); rc,s,e=run(["strings","-a",str(a)],60); digest=sha(a)
    ips=sorted({x for x in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",s) if valid_ip(x)})
    urls=sorted(set(re.findall(r'https?://[^\s"\'<>]+',s)))
    dom=sorted(set(re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b",s)))
    x={"timestamp":ts(),"apk":str(a),"sha256":digest,"ipv4":ips,"urls":urls[:10000],"domains":dom[:10000],"ioc_ip_matches":sorted(set(ips)&iocs)}
    (out/"static_iocs.json").write_text(json.dumps(x,indent=2,ensure_ascii=False))
    print("[+] SHA256",digest);print("[+] IPv4",len(ips),"URLs",len(urls),"Domains",len(dom))
def monitor(out,interval,duration,iocs,target):
    rc,o,e=adb(["devices"])
    if "\tdevice" not in o:print("[-] No ADB device");return 1
    out.mkdir(parents=True,exist_ok=True); jf=out/"evidence.jsonl"; jf.unlink(missing_ok=True)
    up=uid_packages(); target_uid=next((u for u,p in up.items() if target in p),"") if target else ""
    if target:print("[+] Target",target,"UID",target_uid or "NOT FOUND")
    seen=set(); counts=defaultdict(int); start=time.time()
    print("[+] Monitoring. Ctrl-C to stop.")
    try:
      while not duration or time.time()-start<duration:
        up=uid_packages(); im=pid_inodes(); pm=pmap()
        for r in sockets():
          ip=r["remote_ip"]
          if not ip or ip in {"0.0.0.0","::"}:continue
          if target_uid and str(r["uid"])!=str(target_uid):continue
          k=(r["proto"],r["local_ip"],r["local_port"],ip,r["remote_port"],r["state"],r["inode"])
          counts[(ip,r["remote_port"],r["proto"])]+=1
          if k in seen:continue
          seen.add(k)
          pids=sorted(im.get(r["inode"],[])); procs=[pm[p] for p in pids if p in pm]
          s,w=score(r,counts[(ip,r["remote_port"],r["proto"])],iocs)
          if target and str(r["uid"])==str(target_uid):w.append("TARGET_PACKAGE_UID_MATCH")
          rec={"timestamp":ts(),**r,"packages_from_uid":up.get(str(r["uid"]),[]),"pids_from_inode":pids,"processes_from_pid":procs,"target_package":target or None,"event_count":counts[(ip,r["remote_port"],r["proto"])],"score":s,"reasons":w,"ioc":ip in iocs}
          with open(jf,"a",encoding="utf-8") as f:f.write(json.dumps(rec,ensure_ascii=False)+"\n")
          print(json.dumps(rec,ensure_ascii=False))
        time.sleep(max(1,interval))
    except KeyboardInterrupt:print("\n[+] Stopped")
def capture(out,iface,duration):
    if not shutil.which("tcpdump"):print("[-] tcpdump missing");return 1
    out.mkdir(parents=True,exist_ok=True); pcap=out/"traffic.pcap"
    p=subprocess.Popen(["tcpdump","-i",iface,"-nn","-U","-w",str(pcap)])
    try:time.sleep(duration) if duration else p.wait()
    except KeyboardInterrupt:pass
    finally:
      p.terminate()
      try:p.wait(timeout=5)
      except:p.kill()
    print("[+] PCAP",pcap)
def report(out):
    f=out/"evidence.jsonl"
    if not f.exists():print("[-] No evidence");return
    agg={}
    for ln in f.read_text(errors="ignore").splitlines():
      r=json.loads(ln); k=(r["remote_ip"],r["remote_port"],r["proto"])
      x=agg.setdefault(k,{"events":0,"max_score":0,"uids":set(),"packages":set(),"pids":set(),"processes":set(),"reasons":set()})
      x["events"]+=1;x["max_score"]=max(x["max_score"],r["score"]);x["uids"].add(str(r["uid"]));x["packages"].update(r["packages_from_uid"]);x["pids"].update(r["pids_from_inode"]);x["processes"].update(r["processes_from_pid"]);x["reasons"].update(r["reasons"])
    rows=[]
    for (ip,port,proto),x in sorted(agg.items(),key=lambda z:z[1]["max_score"],reverse=True):
      rows.append({"remote":f"{ip}:{port}","proto":proto,"events":x["events"],"max_score":x["max_score"],"uids":sorted(x["uids"]),"packages":sorted(x["packages"]),"pids":sorted(x["pids"]),"processes":sorted(x["processes"]),"reasons":sorted(x["reasons"])})
    (out/"report.json").write_text(json.dumps(rows,indent=2,ensure_ascii=False))
    with open(out/"report.csv","w",newline="",encoding="utf-8") as fp:
      w=csv.DictWriter(fp,fieldnames=rows[0].keys() if rows else ["remote","proto","events","max_score","uids","packages","pids","processes","reasons"]);w.writeheader()
      for r in rows:w.writerow({k:";".join(v) if isinstance(v,list) else v for k,v in r.items()})
    for r in rows:print(f"\n{r['remote']} [{r['proto']}] score={r['max_score']} events={r['events']}\n  packages: {', '.join(r['packages']) or '-'}\n  PIDs: {', '.join(r['pids']) or '-'}\n  reasons: {', '.join(r['reasons']) or '-'}")
def main():
    a=argparse.ArgumentParser(description="Android C2 Hunter v2"); s=a.add_subparsers(dest="mode",required=True)
    p=s.add_parser("static");p.add_argument("apk");p.add_argument("-o","--out",default="c2hunter-static");p.add_argument("--iocs",default="")
    p=s.add_parser("monitor");p.add_argument("-o","--out",default="c2hunter-live");p.add_argument("-i","--interval",type=int,default=1);p.add_argument("-t","--duration",type=int,default=0);p.add_argument("--iocs",default="");p.add_argument("-p","--package",default="")
    p=s.add_parser("capture");p.add_argument("-i","--interface",required=True);p.add_argument("-o","--out",default="c2hunter-capture");p.add_argument("-t","--duration",type=int,default=60)
    p=s.add_parser("report");p.add_argument("-o","--out",default="c2hunter-live")
    x=a.parse_args()
    if x.mode=="static":static(Path(x.apk),Path(x.out),load_iocs(x.iocs))
    elif x.mode=="monitor":monitor(Path(x.out),x.interval,x.duration,load_iocs(x.iocs),x.package)
    elif x.mode=="capture":capture(Path(x.out),x.interface,x.duration)
    else:report(Path(x.out))
if __name__=="__main__":main()
