// Builds the Python the agent "writes" per task. In MOCK mode we run the same logic in Node.
// In live CreateOS mode this string is written to /tmp/scan.py via sandbox_write then executed.
function buildScanPy(kind, profile = 'standard') {
  const strict = profile === 'strict';
  // kind is informational only — one script handles email + file, like a real agent would write
  return `# Agent-written by PhishShield @ ${new Date().toISOString()} (${kind}, profile=${profile})
import sys, os, re, json, hashlib, zipfile
STRICT = ${strict ? 'True' : 'False'}

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/tmp/target"
KNOWN = [d.strip().lower() for d in os.environ.get("KNOWN_BANK_DOMAINS","chase.com,gtbank.com").split(",") if d.strip()]

def sha256(p):
    h = hashlib.sha256()
    with open(p,'rb') as f:
        for c in iter(lambda: f.read(65536), b''): h.update(c)
    return h.hexdigest()

def urls_of(text):
    return re.findall(r'https?://[^\\s"\\'<>]+', text, re.I)

def domains_of(urls):
    out=[]
    for u in urls:
        m=re.search(r'https?://([^/:\\s]+)', u, re.I)
        if m: out.append(m.group(1).lower())
    return out

BRANDS=["paypal","google","apple","microsoft","amazon","netflix","stripe","chase","bankofamerica",
 "gtbank","firstbank","accessbank","zenithbank","opay","palmpay","kuda","moniepoint","binance"]
SHORTENERS=("bit.ly","tinyurl.com","tinyurl","t.co","goo.gl","is.gd","cutt.ly","rb.gy","ow.ly")
SCAM_PATTERNS=[
 (r'verify your (account|identity|bvn|nin)',"Asks you to verify your account/identity (incl. BVN/NIN)"),
 (r'(suspend|deactivat|lock)(ed|ion)? (your )?account',"Threatens to suspend or lock your account"),
 (r'(urgent|immediately|within 24 hours|act now|final notice)',"Uses urgency pressure"),
 (r'(password|pin|otp|cvv|one[- ]time code)',"Mentions passwords, PINs or OTPs"),
 (r'(gift card|wire transfer|crypto(currency)? wallet|send (the )?funds)',"Asks for hard-to-trace payment"),
 (r'(you have won|lottery|inheritance|claim your prize)',"Prize or windfall bait"),
]
def root_h(h): return ".".join(str(h).lower().split(".")[-2:])
def norm_label(s): return str(s).lower().replace("0","o").replace("1","l").replace("rn","m").replace("-","")
def lev(a,b):
    d=[[i]+[0]*len(b) for i in range(len(a)+1)]
    for j in range(1,len(b)+1): d[0][j]=j
    for i in range(1,len(a)+1):
        for j in range(1,len(b)+1):
            d[i][j]=min(d[i-1][j]+1,d[i][j-1]+1,d[i-1][j-1]+(0 if a[i-1]==b[j-1] else 1))
    return d[len(a)][len(b)]
def imitated_brand(domain):
    label=root_h(domain).split(".")[0]
    if label in BRANDS: return None
    n=norm_label(label)
    for b in BRANDS:
        if n==b or (len(label)>=4 and lev(label,b)<=2) or (b in n and label!=b): return b
    return None
def host_of(u):
    m=re.search(r'https?://([^/:\\s]+)',u,re.I)
    return m.group(1).lower() if m else ""
data=open(TARGET,'rb').read()
try: text=data.decode('utf-8',errors='ignore')
except: text=""
is_email = ("from:" in text.lower()[:2000] and ("authentication-results" in text.lower() or "received:" in text.lower())) or TARGET.endswith(".eml")

score=0; reasons=[]; url_list=urls_of(text); doms=domains_of(url_list)
f=sha256(TARGET); size=len(data)

if is_email:
    low=text.lower()
    auth=re.search(r'authentication-results:[^\\n]+',low)
    auth_s=auth.group(0) if auth else ""
    for k in ["spf","dkim","dmarc"]:
        m=re.search(k+r'=(\\w+)',auth_s)
        v=m.group(1).lower() if m else None
        if v=="pass": reasons.append(f"{k.upper()} passed")
        elif v=="fail":
            score+=10 if k=="dmarc" else (25 if k=="dkim" else 10)
            reasons.append(f"{k.upper()} failed")
        elif "authentication-results" in low: score+=5; reasons.append(f"{k.upper()} result missing")
    fm=re.search(r'^from:\\s*(?:"?([^"<\\n]*?)"?\\s*)?<([^<>\\s\\n]+)>|^from:\\s*([^\\s\\n]+)',text,re.I|re.M)
    from_name=(fm.group(1) or "").strip() if fm else ""
    from_addr=((fm.group(2) or fm.group(3)) if fm else "" or "").lower()
    from_dom=(from_addr.split("@")[1] if "@" in from_addr else "").strip()
    sender_puny=from_dom.startswith("xn--") or ".xn--" in from_dom
    if sender_puny: score+=30; reasons.append("Sender domain uses punycode (possible fake letters)")
    if from_dom and from_dom in KNOWN: reasons.append(f"Sender domain matches known bank domain ({from_dom})")
    elif from_dom:
        kb=next((k for k in KNOWN if k.split('.')[0] in from_dom),None)
        brand=imitated_brand(from_dom)
        if kb or "-secure" in from_dom or "-verify" in from_dom or from_dom.count('.')>3:
            score+=30; reasons.append(f"Lookalike sender domain: {from_dom}")
        elif brand: score+=35; reasons.append(f"{from_dom} looks like {brand} but isn't")
        else: score+=15; reasons.append(f"Sender domain {from_dom} not in known bank domains")
    claimed=next((b for b in BRANDS if b in from_name.lower().replace(" ","")),None)
    if claimed and from_dom and not root_h(from_dom).startswith(claimed):
        score+=30; reasons.append(f'Name says "{from_name}" but it came from {from_dom}')
    pairs=[(m.group(1),re.sub(r'<[^>]+>',' ',m.group(2))) for m in re.finditer(r'<a\\b[^>]*href\\s*=\\s*["\\']([^"\\']+)["\\'][^>]*>([\\s\\S]*?)</a>',text,re.I)]
    pairs+= [(m.group(2),m.group(1)) for m in re.finditer(r'\\[\\[LINK text="(.*?)" href="(.*?)"\\]\\]',text)]
    flagged=set()
    for href,txt in pairs[:50]:
        h=host_of(href)
        if not h or href.startswith("mailto:"): continue
        sm=re.search(r'([a-z0-9-]+\\.)+[a-z]{2,}',txt,re.I)
        shown=sm.group(0).lower() if sm else ""
        if shown and root_h(shown)!=root_h(h) and not h.endswith("google.com"):
            score+=30; flagged.add(h); reasons.append(f"Link shows {shown} but goes to {h}")
        if re.match(r'^\\d+\\.\\d+\\.\\d+\\.\\d+$',h) and ('ip:'+h) not in flagged:
            score+=25; flagged.add('ip:'+h); reasons.append(f"Link goes to a bare IP address ({h})")
        lb=imitated_brand(h)
        if lb and ('brand:'+h) not in flagged:
            score+=35; flagged.add('brand:'+h); reasons.append(f"Link domain {h} imitates {lb}")
    for hd in set([host_of(p[0]) for p in pairs if host_of(p[0])]+doms):
        if KNOWN and hd not in KNOWN and not any(hd.endswith('.'+k) for k in KNOWN) and not any(f.endswith(hd) for f in flagged):
            score+=25; reasons.append(f"Link goes to non-bank domain: {hd}"); break
    if any(s==d or s in d for d in doms+[host_of(p[0]) for p in pairs] for s in SHORTENERS):
        score+=15; reasons.append("Shortened URL hides destination")
    if "xn--" in text and not sender_puny: score+=25; reasons.append("Punycode (IDN homograph) detected")
    subj=re.search(r'^subject:[^\\n]*',text,re.I|re.M)
    body_text=((subj.group(0) if subj else "")+"\\n"+text)
    for pat,why in SCAM_PATTERNS:
        if re.search(pat,body_text,re.I): score+=10; reasons.append(why)
    if re.search(r'\\b(otp|pin|cvv|password)\\b',low) and re.search(r'urgent|suspend|24\\s*hours|immediately|verify now',low):
        score+=20; reasons.append("Urgent tone + credential (PIN/OTP) request")
else:
    if b'/JS' in data or b'/JavaScript' in data: score+=25; reasons.append("PDF contains embedded JavaScript (/JS)")
    if b'/Launch' in data or b'/OpenAction' in data or b'/EmbeddedFiles' in data:
        score+=20; reasons.append("PDF has launch/open-action or embedded files")
    is_zip = data[:2]==b'PK'
    if is_zip:
        try:
            z=zipfile.ZipFile(TARGET); names=z.namelist()
            if any('vbaProject.bin' in n for n in names):
                score+=25; reasons.append("Office doc contains VBA macros")
                blob=b" ".join([z.read(n) for n in names if n.endswith('.xml')][:20])
                if b'http' in blob or b'powershell' in blob.lower() or b'shell' in blob.lower():
                    score+=20; reasons.append("Macro-adjacent content references URL/shell")
        except Exception as e: reasons.append(f"Zip parse note: {e}")
    if data[:2]==b'MZ':
        reasons.append("Windows executable (static-only, not executed)")
        if url_list: score+=20; reasons.append(f"EXE references {len(url_list)} URL(s)")
        if re.search(r'password|credential|mimikatz|powershell',text,re.I): score+=25; reasons.append("EXE strings contain credential/shell keywords")
    if len(url_list)>=3: score+=10; reasons.append(f"{len(url_list)} embedded URLs")

if STRICT: score = int(score * 1.25 + 0.5)  # match JS Math.round (py round() is banker's)
MAL, SUS = (50, 25) if STRICT else (70, 40)
verdict="Malicious" if score>=MAL else ("Suspicious" if score>=SUS else "Verified")
if (not is_email) and verdict=="Verified": verdict="Verified"  # UI maps to Safe
print(json.dumps({"verdict":verdict,"score":score,"reasons":reasons or ["No red flags found"],
  "iocs":{"sha256":f,"urls":url_list[:20],"domains":sorted(set(doms))[:20]},
  "kind":"email" if is_email else "file","size":size}))
`;
}

module.exports = { buildScanPy };
