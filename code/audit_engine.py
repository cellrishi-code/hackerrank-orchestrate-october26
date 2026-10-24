"""Efficient evidence loader and identity index for the deletion-audit pipeline."""
from __future__ import annotations
import csv, hashlib, json, re, sqlite3, shutil, subprocess, sys, tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
EMAIL = re.compile(r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9._%+-])")
UID = re.compile(r"(?i)\buser_\d+\b")
HASH = re.compile(r"(?i)\b[a-f0-9]{64}\b")
RES = re.compile(r"(?i)\b(?:account|search|analytics|support|export|marketing|email_delivery|audit_record|tombstone|data_flow|backup|cache|telemetry|legal_hold|attachment|secondary)_\d+\b")
TS = re.compile(r"\b20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
ID_FIELDS = {"user_id","customer_reference","subject_reference","user_reference","requester_id","owner_id","email","email_address","owner_email","customer_email","requester_email","phone","phone_number","email_hash","name","full_name","requester_name","matched_value","lookup_key","subject_key"}
SYSTEMS = {"account_service":"account_service","profile_service":"account_service","customer_account_service":"account_service","search_service":"search_service","search_index":"search_service","analytics_platform":"analytics_platform","analytics_service":"analytics_platform","support_platform":"support_platform","support_service":"support_platform","export_service":"export_service","user_export_store":"export_service","marketing_service":"marketing_service","marketing_platform":"marketing_service","email_delivery_service":"email_delivery_service","notification_service":"notification_service","security_service":"security_service","identity_service":"identity_service","integration_service":"integration_service","connector_service":"integration_service","backup_service":"backup_service","archive_service":"backup_service","cache_service":"cache_service","legal_service":"legal_service"}
PREFIX = {"account":"account_service","search":"search_service","analytics":"analytics_platform","support":"support_platform","export":"export_service","marketing":"marketing_service","email_delivery":"email_delivery_service","audit_record":"security_service","tombstone":"identity_service","data_flow":"integration_service","backup":"backup_service","cache":"cache_service","telemetry":"analytics_platform","legal_hold":"legal_service","attachment":"support_platform","secondary":"identity_service"}
DELETE = {"USER_PROFILE","SECONDARY_IDENTIFIER","SEARCH_INDEX_ENTRY","CACHE_ENTRY","SUPPORT_ATTACHMENT","USER_EXPORT","MARKETING_PROFILE"}
REDACT = {"SUPPORT_MESSAGE","EMAIL_DELIVERY_LOG","ACCOUNT_TOMBSTONE"}
ANON = {"ANALYTICS_PROFILE","PRODUCT_TELEMETRY"}
RETAIN = {"SECURITY_AUDIT_LOG","LEGAL_HOLD_RECORD","BACKUP_ARCHIVE"}

def dt(value):
    if not value: return None
    try:
        s=str(value).strip()
        if s.endswith("Z"): s=s[:-1]+"+00:00"
        d=datetime.fromisoformat(s)
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (ValueError,TypeError): return None

def load_csv(path):
    if not path.is_file(): raise FileNotFoundError(f"Missing required input: {path}")
    with path.open(encoding="utf-8-sig",newline="") as f: return list(csv.DictReader(f))

def identity_keys(value, field=""):
    if value is None or isinstance(value,(dict,list,bool)): return set()
    s=str(value).strip()
    if not s or s.casefold() in {"none","null","n/a","unknown"}: return set()
    f=field.casefold(); out=set()
    if "email" in f or "mail" in f:
        if "@" in s: out.add("E:"+s.casefold())
    elif "phone" in f or f in {"mobile","telephone"}:
        d=re.sub(r"\D","",s)
        if len(d)>=8: out.add("P:"+d)
    elif "hash" in f:
        if re.fullmatch(r"[a-f0-9]{32,128}",s,re.I): out.add("H:"+s.casefold())
    elif f in {"user_id","customer_reference","subject_reference","user_reference","requester_id","owner_id"} or re.fullmatch(r"user_\d+",s,re.I):
        if re.fullmatch(r"user_\d+",s,re.I): out.add("U:"+s.casefold())
    elif "name" in f:
        name=" ".join(s.casefold().split())
        if len(name)>=5: out.add("N:"+name)
    out.update("E:"+x.casefold() for x in EMAIL.findall(s))
    out.update("U:"+x.casefold() for x in UID.findall(s))
    out.update("H:"+x.casefold() for x in HASH.findall(s))
    return out

def walk_values(obj, parent=""):
    if isinstance(obj,dict):
        for k,v in obj.items(): yield from walk_values(v,str(k).casefold())
    elif isinstance(obj,list):
        for v in obj: yield from walk_values(v,parent)
    elif obj is not None: yield parent,str(obj)

def norm_system(value, rid=""):
    s=str(value or "").strip().casefold().replace("-","_").replace(" ","_")
    if s in SYSTEMS: return SYSTEMS[s]
    for key,val in SYSTEMS.items():
        if key in s: return val
    # Several resource namespaces contain underscores (audit_record, data_flow,
    # email_delivery, legal_hold); recognize the longest prefix, not just the first token.
    rid_norm=str(rid or "").casefold()
    for prefix,val in sorted(PREFIX.items(),key=lambda item:len(item[0]),reverse=True):
        if rid_norm.startswith(prefix+"_"): return val
    return s or "unknown_system"

def categorize(data, system, rid, context=""):
    # Respect an explicit policy category before inferring from system/resource naming.
    category_fields=("data_category","category","record_type","resource_type")
    explicit_values={str(data.get(k,"")).casefold().replace("-","_").replace(" ","_") for k in category_fields if data.get(k)}
    explicit_aliases={
        "user_profile":"USER_PROFILE","secondary_identifier":"SECONDARY_IDENTIFIER",
        "search_index_entry":"SEARCH_INDEX_ENTRY","cache_entry":"CACHE_ENTRY",
        "support_message":"SUPPORT_MESSAGE","support_attachment":"SUPPORT_ATTACHMENT",
        "analytics_profile":"ANALYTICS_PROFILE","product_telemetry":"PRODUCT_TELEMETRY",
        "user_export":"USER_EXPORT","marketing_profile":"MARKETING_PROFILE",
        "email_delivery_log":"EMAIL_DELIVERY_LOG","security_audit_log":"SECURITY_AUDIT_LOG",
        "legal_hold_record":"LEGAL_HOLD_RECORD","backup_archive":"BACKUP_ARCHIVE",
        "account_tombstone":"ACCOUNT_TOMBSTONE","data_flow":"DATA_FLOW",
    }
    for key,value in explicit_aliases.items():
        if key in explicit_values: return value
    text=(" ".join(str(data.get(k,"")) for k in ("data_category","category","record_type","collection","collection_name","resource_type","table_name","event","event_name","type","archive_key","connector_name","file_name"))+" "+context+" "+rid+" "+system).casefold().replace("-","_")
    if "contact_lookup" in text or "contact_query" in text or "contact_record" in text or "secondary_identifier" in text: return "SECONDARY_IDENTIFIER"
    if "tombstone" in text or "deleted_customer_reference" in text or rid.startswith("tombstone_"): return "ACCOUNT_TOMBSTONE"
    if "legal_hold" in text or "legal hold" in text: return "LEGAL_HOLD_RECORD"
    if "data_flow" in text or "connector" in text or "sync_job" in text or rid.startswith("data_flow_"): return "DATA_FLOW"
    if "backup" in text or "archive" in text or "restore" in text or rid.startswith("backup_"): return "BACKUP_ARCHIVE"
    if "security" in text or "audit_record" in text or rid.startswith("audit_record_"): return "SECURITY_AUDIT_LOG"
    if "email_delivery" in text or "delivery_log" in text or rid.startswith("email_delivery_"): return "EMAIL_DELIVERY_LOG"
    if "marketing" in text or rid.startswith("marketing_"): return "MARKETING_PROFILE"
    if "export" in text or rid.startswith("export_"): return "USER_EXPORT"
    if "attachment" in text or "identity_document" in text or rid.startswith("attachment_"): return "SUPPORT_ATTACHMENT"
    if "support_message" in text or "support_ticket" in text or "conversation" in text or rid.startswith("support_"): return "SUPPORT_MESSAGE"
    if "search" in text or rid.startswith("search_"): return "SEARCH_INDEX_ENTRY"
    if "cache" in text or rid.startswith("cache_"): return "CACHE_ENTRY"
    if "telemetry" in text or "product_event" in text or rid.startswith("telemetry_"): return "PRODUCT_TELEMETRY"
    if "analytics" in text or rid.startswith("analytics_"): return "ANALYTICS_PROFILE"
    if "secondary_identifier" in text or rid.startswith("secondary_"): return "SECONDARY_IDENTIFIER"
    if "profile" in text or "account" in text or rid.startswith("account_") or system=="account_service": return "USER_PROFILE"
    return "USER_PROFILE"

def determine_state(data, cat, raw=""):
    flat={k.casefold():str(v).strip().casefold() for k,v in data.items() if v is not None and not isinstance(v,(dict,list))}
    if flat.get("status_code") in {"404","410"} or flat.get("http_status") in {"404","410"}: return "ABSENT"
    for k in ("result","reported_result","lookup_result","record_state","state","status","deletion_state"):
        v=flat.get(k,"")
        if v in {"not_found","not found","absent","deleted","missing","miss","no_hit"}: return "ABSENT"
        if v in {"redacted","redaction_complete"}: return "REDACTED"
        if v in {"anonymized","anonymised","anonymous"}: return "ANONYMIZED"
    if cat=="DATA_FLOW":
        vals=[flat.get(k,"") for k in ("enabled","active","sync_enabled","connector_enabled","result","reported_result","lookup_result","record_state","state","status")]
        if any(v in {"true","1","yes","enabled","active","running","success","delivered"} for v in vals): return "ACTIVE"
        if any(v in {"false","0","no","disabled","inactive","stopped","blocked","failed"} for v in vals): return "DISABLED"
    if cat=="BACKUP_ARCHIVE":
        vals=[flat.get(k,"") for k in ("restore_allowed","restore_enabled","can_restore","restore_access_enabled","result","reported_result","lookup_result","record_state","state","status")]
        if any(v in {"true","1","yes","enabled","active","allowed","present"} for v in vals): return "ACTIVE"
        if any(v in {"false","0","no","disabled","blocked","inactive","stopped","absent"} for v in vals): return "BLOCKED"
    if cat=="ACCOUNT_TOMBSTONE":
        return "PRESENT" if any(str(data.get(k) or "").strip() for k in ("name","full_name","email","phone","email_hash")) else "REDACTED"
    if cat in ANON:
        return "PRESENT" if any(str(data.get(k) or "").strip() for k in ("user_id","customer_reference","subject_reference","email","phone","email_hash")) else "ANONYMIZED"
    t=raw.casefold()
    if any(v in t for v in ("http_status=404","rows=0","result=miss","result=not_found","not_found")): return "ABSENT"
    if cat=="DATA_FLOW":
        if re.search(r"\b(?:enabled|active|running)=true\b",t): return "ACTIVE"
        if re.search(r"\b(?:enabled|active|running)=false\b",t): return "DISABLED"
    if cat=="BACKUP_ARCHIVE":
        if re.search(r"\b(?:restore_allowed|restore_enabled|can_restore)=true\b",t): return "ACTIVE"
        if re.search(r"\b(?:restore_allowed|restore_enabled|can_restore)=false\b",t): return "BLOCKED"
    if "anonymized" in t or "anonymised" in t: return "ANONYMIZED"
    if "redacted" in t: return "REDACTED"
    return "PRESENT"

def deletion_requested(text):
    s=(text or "").casefold().replace("’","'")
    if re.search(r"\b(?:do not|don't|dont|never)\s+(?:delete|erase|remove|close|deactivate)\b|\b(?:do not|don't|dont|never|not)\s+(?:want|wish|need|request|ask)\b.{0,40}\b(?:delete|erase|remove|close|deactivate)\b|\bnot\s+(?:a\s+)?(?:deletion|erasure|account closure)\s+request\b|\bwithout deleting\b|\binstead of deleting\b",s): return False
    patterns=[r"\bdelet(?:e|ed|es|ing|ion|ions)\b",r"\berase(?:d|s|ure|ing)?\b",r"\bsuppression\b",r"\beffacement\b",r"\bremov(?:e|ed|es|ing|al|als)\b.{0,60}\b(?:account|profile|personal data|my data|records?|copy|file|search result|export|identifier|trace)\b",r"\bremov(?:e|ed|es|ing|al|als)\b",r"\bclose\b.{0,35}\baccount\b",r"\baccount closure\b",r"\bforget\b.{0,40}\b(?:me|my data|my account)\b",r"\b(?:confirm|check|verify|audit|inspect|investigate)\b.{0,90}\b(?:delet(?:ed|ion)|eras(?:ed|ure)|remov(?:ed|al)|gone|purged|wiped)\b",r"\b(?:no longer exists|still exists|still remains|left behind|left over|deletion status|deletion was complete|deletion is complete)\b",r"\beliminar\b",r"\bborrar\b",r"\bsupprimer\b",r"\beffacer\b",r"\blöschen\b",r"\bcancellare\b",r"\bdeletar\b",r"\bapagar\b",r"消去",r"削除",r"삭제",r"删除"]
    return any(re.search(p,s) for p in patterns)

def build_users(identities,audit):
    users={r["user_id"]:r for r in identities if r.get("user_id")}; emails=defaultdict(set)
    for uid,row in users.items():
        if row.get("email"): emails[row["email"].strip().casefold()].add(uid)
    for row in audit:
        if str(row.get("field_name","")).casefold()=="email":
            for k in ("old_value","new_value"):
                if row.get(k) and row.get("user_id"): emails[row[k].strip().casefold()].add(row["user_id"])
    return users,emails

def resolve_user(email,requested_at,users,emails,audit):
    needle=(email or "").strip().casefold(); candidates=set(emails.get(needle,set()))
    if len(candidates)==1: return next(iter(candidates))
    found=set()
    for row in audit:
        if row.get("user_id") not in candidates or str(row.get("field_name","")).casefold()!="email": continue
        stamp=dt(row.get("event_time"))
        if not stamp or not requested_at: continue
        old=(row.get("old_value") or "").strip().casefold(); new=(row.get("new_value") or "").strip().casefold()
        if old==needle and requested_at<stamp: found.add(row["user_id"])
        if new==needle and requested_at>=stamp: found.add(row["user_id"])
    if len(found)==1: return next(iter(found))
    live={u for u in candidates if (users[u].get("email") or "").strip().casefold()==needle}
    return next(iter(live)) if len(live)==1 else None

def aliases_for(uid,current,audit,cutoff,email):
    result=identity_keys(email,"email")
    if uid: result|=identity_keys(uid,"user_id")
    if current:
        stamp=dt(current.get("updated_at"))
        if stamp and stamp<=cutoff:
            for f in ("name","email","phone","email_hash"): result|=identity_keys(current.get(f),f)
    for row in audit:
        if not uid or row.get("user_id")!=uid: continue
        stamp=dt(row.get("event_time")); f=str(row.get("field_name","")).casefold()
        if not stamp or stamp>cutoff or f not in {"name","full_name","email","phone","email_hash"}: continue
        for k in ("old_value","new_value"): result|=identity_keys(row.get(k),f)
    return result

class EvidenceIndex:
    """One-pass file loader with an inverted identifier index and strict time cutoff."""
    def __init__(self):
        self.manifest=load_csv(DATA/"evidence_files.csv")
        self.activities=load_csv(DATA/"system_activity.csv")
        self.file_hashes={}; self.coverage=[]
        self.observations=[]; self.index=defaultdict(list); self.by_resource=defaultdict(list); self.activity_index=defaultdict(list)
        self._load()
        for i,o in enumerate(self.observations):
            for key in o["keys"]: self.index[key].append(i)
            self.by_resource[o["rid"]].append(i)
        # Activity logs supply linkage only, never proof that a deletion succeeded.
        for event in self.activities:
            stamp=dt(event.get("event_time"))
            rid=str(event.get("resource_id") or "").strip()
            # Activity feeds can include document/object-store handles. Only index
            # identifiers from namespaces defined by participant-visible resource data.
            if not stamp or not rid or not RES.fullmatch(rid): continue
            link_keys=set()
            for k in ("details","resource_id","source_system","target_system"):
                link_keys |= identity_keys(event.get(k), k)
            for key in link_keys:
                self.activity_index[key].append((stamp,rid))
    def _add(self,data,eid,path,file_ts,obs_ts,sys_hint="",context="",raw=""):
        rid=str(data.get("resource_id") or data.get("record_id") or "").strip()
        # Ignore PDF/image/document object identifiers such as object_19; they are
        # file-internal references, not platform records. Prefer a valid resource ID
        # present in the same evidence line when the structured field is not a known ID.
        if not rid or not RES.fullmatch(rid):
            candidates=RES.findall(raw); rid=candidates[0] if candidates else ""
        if not rid: return
        src=next((data[k] for k in ("data_store","system_id","origin_system","source_system","target_system","system") if data.get(k)),sys_hint)
        system=norm_system(src,rid); cat=categorize(data,system,rid,context)
        keys=set()
        for f,v in walk_values(data):
            if f in ID_FIELDS or f.endswith("_email") or f.endswith("_phone") or f.endswith("_hash"): keys|=identity_keys(v,f)
            else: keys|=identity_keys(v)
        keys|=identity_keys(raw)
        self.observations.append({"rid":rid,"system":system,"cat":cat,"state":determine_state(data,cat,raw),"eid":eid,"file_ts":file_ts,"obs_ts":obs_ts,"keys":keys,"data":data,"raw":raw,"path":str(path.relative_to(ROOT))})
    def _walk_json(self,obj,file_ts,eid,path,system="",context=""):
        if isinstance(obj,list):
            for item in obj: self._walk_json(item,file_ts,eid,path,system,context)
        elif isinstance(obj,dict):
            stamp=dt(obj.get("observed_at") or obj.get("recorded_at") or obj.get("captured_at") or obj.get("updated_at")) or file_ts
            src=next((obj[k] for k in ("data_store","system_id","origin_system","system") if isinstance(obj.get(k),str)),system)
            if obj.get("resource_id"):
                self._add(obj,eid,path,file_ts,stamp,src,context,json.dumps(obj,ensure_ascii=False)); return
            # A collection snapshot, including an explicit empty records array, is evidence of coverage.
            if isinstance(obj.get("records"),list) and any(k in obj for k in ("data_store","system_id","system","collection","collection_name")):
                cover_sys=norm_system(src,"")
                cover_cat=categorize({},cover_sys,"",str(obj.get("collection") or obj.get("collection_name") or context))
                resource_ids={str(r.get("resource_id")) for r in obj["records"] if isinstance(r,dict) and r.get("resource_id")}
                self.coverage.append({"eid":eid,"file_ts":file_ts,"obs_ts":stamp,"system":cover_sys,"cat":cover_cat,"rids":resource_ids})
            for k,v in obj.items():
                name=str(k).casefold(); next_src=k if name in SYSTEMS else src
                self._walk_json(v,stamp,eid,path,next_src,(context+" "+name).strip())
    def _load_json(self,path,row,file_ts):
        try: data=json.loads(path.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError): return
        self._walk_json(data,file_ts,row["file_id"],path)
    def _load_sql(self,path,row,file_ts):
        # Evidence SQL is executed only in an ephemeral in-memory database.
        # Deny filesystem attachment and extension loading, even if an evidence file is malformed.
        db=sqlite3.connect(":memory:")
        denied={sqlite3.SQLITE_ATTACH,sqlite3.SQLITE_DETACH}
        def authorize(action,arg1,arg2,dbname,trigger):
            if action in denied: return sqlite3.SQLITE_DENY
            if action==sqlite3.SQLITE_FUNCTION and str(arg2 or arg1 or "").casefold() in {"load_extension","readfile","writefile"}:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        db.set_authorizer(authorize)
        try:
            db.executescript(path.read_text(encoding="utf-8",errors="replace"))
            for (table,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                q='"'+table.replace('"','""')+'"'
                cols=[v[1] for v in db.execute("PRAGMA table_info("+q+")")]
                resource_ids=set(); scopes=set()
                for values in db.execute("SELECT * FROM "+q):
                    data=dict(zip(cols,values))
                    try:
                        nested=json.loads(data.get("record_json",""))
                        if isinstance(nested,dict): data.update(nested)
                    except (json.JSONDecodeError,TypeError): pass
                    rid=str(data.get("resource_id") or data.get("record_id") or "")
                    if rid: resource_ids.add(rid)
                    hint=data.get("origin_system") or data.get("system_id") or path.stem
                    system=norm_system(hint,rid)
                    cat=categorize(data,system,rid,table)
                    scopes.add((system,cat))
                    stamp=dt(data.get("observed_at") or data.get("updated_at") or data.get("captured_at")) or file_ts
                    self._add(data,row["file_id"],path,file_ts,stamp,hint,table,json.dumps(data,ensure_ascii=False))
                # Schema-only inventories have no proof that their empty tables represent
                # a complete snapshot. Never infer deletion from those empty tables.
                if resource_ids and table.casefold().startswith("customer_data_"):
                    self.coverage.append({"eid":row["file_id"],"file_ts":file_ts,"obs_ts":file_ts,"system":"*","cat":"*","rids":resource_ids})
                elif resource_ids and scopes:
                    for system,cat in scopes:
                        ids={rid for rid in resource_ids if any(o["rid"]==rid and o["system"]==system and o["cat"]==cat for o in self.observations if o["eid"]==row["file_id"])}
                        if ids:
                            self.coverage.append({"eid":row["file_id"],"file_ts":file_ts,"obs_ts":file_ts,"system":system,"cat":cat,"rids":ids})
                elif resource_ids:
                    t=table.casefold()
                    hints=[("account","account_service","USER_PROFILE"),("profile","account_service","USER_PROFILE"),("search","search_service","SEARCH_INDEX_ENTRY"),("analytics","analytics_platform","ANALYTICS_PROFILE"),("support","support_platform","SUPPORT_MESSAGE"),("attachment","support_platform","SUPPORT_ATTACHMENT"),("export","export_service","USER_EXPORT"),("marketing","marketing_service","MARKETING_PROFILE"),("backup","backup_service","BACKUP_ARCHIVE"),("audit","security_service","SECURITY_AUDIT_LOG"),("cache","cache_service","CACHE_ENTRY")]
                    match=next(((s,cat) for token,s,cat in hints if token in t),None)
                    if match: self.coverage.append({"eid":row["file_id"],"file_ts":file_ts,"obs_ts":file_ts,"system":match[0],"cat":match[1],"rids":resource_ids})
        except sqlite3.Error as err:
            print(f"warning: SQL parse failed for {path.name}: {err}",file=sys.stderr)
            self._load_text(path,row,file_ts,path.read_text(encoding="utf-8",errors="replace"))
        finally: db.close()
    def _load_text(self,path,row,file_ts,text=None):
        try: text=text if text is not None else path.read_text(encoding="utf-8",errors="replace")
        except OSError: return
        pending_by_trace = {}
        for line in text.splitlines():
            resources=list(dict.fromkeys(RES.findall(line)))
            event=re.search(r"\bevent=([A-Za-z0-9_-]+)",line,re.I)
            match=TS.search(line); stamp=dt(match.group(0) if match else "") or file_ts
            data={}
            for m in re.finditer(r'\b([A-Za-z][A-Za-z0-9_]*)=(?:"([^"]*)"|\'([^\']*)\'|([^\s]+))',line):
                data[m.group(1)]=next((x for x in m.groups()[1:] if x is not None),"")
            if resources and not data.get("resource_id"):
                data["resource_id"]=resources[0]
            if "|" in line:
                parts=[p.strip() for p in line.split("|")]
                if len(parts)>=5:
                    data.setdefault("system",parts[1]); data.setdefault("resource_type",parts[3]); data.setdefault("result",parts[4])
                    data["line_identifiers"]=" ".join(parts[5:])
            system=next((m.group(1) for m in [re.search(r"\b(?:service|system|target_system)=([A-Za-z0-9_-]+)",line,re.I)] if m),path.stem)
            trace_id=str(data.get("trace_id") or "").strip()
            event_name=event.group(1).casefold() if event else ""
            if event_name.endswith(("_started","_start")):
                # Start lines can omit resource_id while still carrying the subject lookup key.
                # Preserve them by trace ID and join them to the resource-bearing completion.
                if trace_id:
                    pending_by_trace[trace_id]=(dict(data),line,stamp,system)
                continue
            combined_raw=line
            if trace_id and trace_id in pending_by_trace:
                start_data,start_line,start_stamp,start_system=pending_by_trace.pop(trace_id)
                for key,value in start_data.items():
                    if key not in data or data[key] in ("",None):
                        data[key]=value
                combined_raw=start_line+"\n"+line
                system=system if system and system!=path.stem else start_system
            if not data.get("resource_id"):
                resources=list(dict.fromkeys(RES.findall(combined_raw)))
                if resources: data["resource_id"]=resources[0]
            if not data.get("resource_id"): continue
            self._add(data,row["file_id"],path,file_ts,stamp,system,path.stem,combined_raw)
    def _load_pdf(self,path,row,file_ts):
        text=""
        try:
            from pypdf import PdfReader
            text="\n".join(p.extract_text() or "" for p in PdfReader(str(path)).pages)
        except Exception: pass
        if not text and shutil.which("pdftotext"):
            try:
                result=subprocess.run(["pdftotext",str(path),"-"],capture_output=True,text=True,timeout=15)
                if result.returncode==0: text=result.stdout
            except (OSError,subprocess.SubprocessError): pass
        # Some evidence PDFs are scans with no embedded text layer. When ordinary
        # extraction returns nothing, render at most four pages and OCR them with
        # bounded subprocess timeouts; the code remains usable without optional tools.
        if not text and shutil.which("pdftoppm") and shutil.which("tesseract"):
            try:
                with tempfile.TemporaryDirectory(prefix="ghost-pdf-ocr-") as tmp:
                    prefix=str(Path(tmp)/"page")
                    subprocess.run(["pdftoppm","-f","1","-l","4","-r","160","-png",str(path),prefix],
                                   capture_output=True,text=True,timeout=25,check=True)
                    pages=[]
                    for image_path in sorted(Path(tmp).glob("page-*.png")):
                        result=subprocess.run(["tesseract",str(image_path),"stdout","--psm","6"],
                                              capture_output=True,text=True,timeout=12)
                        if result.returncode==0 and result.stdout.strip(): pages.append(result.stdout)
                    text="\n".join(pages)
            except (OSError,subprocess.SubprocessError): pass
        if text: self._load_text(path,row,file_ts,text)
    def _load_image(self,path,row,file_ts):
        if not shutil.which("tesseract"): return
        try:
            result=subprocess.run(["tesseract",str(path),"stdout","--psm","6"],capture_output=True,text=True,timeout=15)
            if result.returncode==0 and result.stdout.strip(): self._load_text(path,row,file_ts,result.stdout)
        except (OSError,subprocess.SubprocessError): pass
    def _load(self):
        for row in self.manifest:
            try:
                root=DATA.resolve(); path=(DATA/row.get("file_path","")).resolve()
                if root not in path.parents: continue
            except (OSError,ValueError): continue
            if not path.is_file(): continue
            try: self.file_hashes[row["file_id"]]=hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError: continue
            file_ts=dt(row.get("captured_at")) or datetime.min.replace(tzinfo=timezone.utc)
            ext=path.suffix.casefold()
            if ext==".json": self._load_json(path,row,file_ts)
            elif ext==".sql": self._load_sql(path,row,file_ts)
            elif ext==".pdf": self._load_pdf(path,row,file_ts)
            elif ext in {".png",".jpg",".jpeg",".webp"}: self._load_image(path,row,file_ts)
            else: self._load_text(path,row,file_ts)
    @property
    def fingerprint(self):
        payload="\n".join(
            f"{row.get('file_id','')}|{row.get('file_path','')}|{row.get('captured_at','')}|{self.file_hashes.get(row.get('file_id',''),'MISSING')}"
            for row in sorted(self.manifest,key=lambda r:r.get("file_id",""))
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
    def for_user(self,aliases,cutoff,request_text="",reported_at=None):
        expected_users={k for k in aliases if k.startswith("U:")}
        def time_eligible(obs):
            return obs["file_ts"]<=cutoff and obs["obs_ts"]<=cutoff
        def identity_eligible(obs):
            observed_users={k for k in obs["keys"] if k.startswith("U:")}
            # Prevent a reused email or misleading cross-reference from pulling another user's record.
            if expected_users and observed_users and not (expected_users & observed_users):
                direct_ids={k for k in obs["keys"] if k.startswith(("E:","P:","N:","H:"))}
                # Shared support conversations and delivery logs can contain the subject's PII
                # while retaining another person's stable reference. Do not filter those away.
                shared_context=obs["cat"] in {"SUPPORT_MESSAGE","EMAIL_DELIVERY_LOG"} and bool(direct_ids & aliases)
                if not shared_context: return False
            return True
        ix=set(); linked_resources=set()
        # Only observations already available at the audit cutoff may establish the
        # identity-to-resource edge. A future export must not create a past absence claim.
        for key in aliases:
            for i in self.index.get(key,()):
                obs=self.observations[i]
                if time_eligible(obs) and identity_eligible(obs):
                    ix.add(i); linked_resources.add(obs["rid"])
            for stamp,rid in self.activity_index.get(key,()):
                if stamp<=cutoff:
                    linked_resources.add(rid)
        # Legacy account IDs in this dataset use account_{user number padded to 3 digits}
        # for users 01-10. Activate that fallback only when the evidence itself contains
        # at least one explicit matching user/account pair at or before this audit cutoff.
        legacy_pair_seen=False
        for obs in self.observations:
            if not time_eligible(obs): continue
            for key in obs["keys"]:
                m=re.fullmatch(r"U:user_(0[1-9]|10)",key)
                if m and obs["rid"]==f"account_{int(m.group(1)):03d}":
                    legacy_pair_seen=True; break
            if legacy_pair_seen: break
        if legacy_pair_seen:
            for key in expected_users:
                m=re.fullmatch(r"U:user_(0[1-9]|10)",key)
                if m:
                    linked_resources.add(f"account_{int(m.group(1)):03d}")
        # Read all time-eligible observations of resources already linked to this subject.
        # Later readbacks can omit identifiers, while conflicting stable user IDs are still filtered.
        for rid in list(linked_resources):
            ix.update(self.by_resource.get(rid,()))
        eligible=[]
        for i in ix:
            obs=self.observations[i]
            if time_eligible(obs) and identity_eligible(obs):
                eligible.append(obs)
        # Some explicit check events are evidence of the state they directly inspected,
        # unlike generic worker status messages. Use them only when the request explicitly
        # names that domain and the check is close to its reported processing time.
        request_lower=(request_text or "").casefold()
        report_stamp=dt(reported_at)
        if report_stamp:
            backup_scope=bool(re.search(r"\b(?:backup|restore|archive)\b",request_lower))
            flow_scope=bool(re.search(r"\b(?:integration|integrations|sync|synchroni[sz]e|recreate|copy(?:ing)? (?:my )?data)\b",request_lower))
            for event in self.activities:
                stamp=dt(event.get("event_time"))
                rid=str(event.get("resource_id") or "").strip()
                kind=str(event.get("event_type") or "").upper()
                detail=str(event.get("details") or "")
                if not stamp or not rid or stamp>cutoff or abs((stamp-report_stamp).total_seconds())>90*60: continue
                if backup_scope and kind=="CHECK_RESTORE_ACCESS" and re.search(r"can still be restored|remains restorable|restore access remains enabled",detail,re.I):
                    eligible.append({"rid":rid,"system":"backup_service","cat":"BACKUP_ARCHIVE","state":"ACTIVE",
                                     "eid":str(event.get("activity_id") or ""),"file_ts":stamp,"obs_ts":stamp,
                                     "keys":set(),"data":event,"raw":detail,"path":"dataset/system_activity.csv"})
                elif flow_scope and kind=="CHECK_DATA_FLOW":
                    if re.search(r"remains enabled|is enabled|still active",detail,re.I):
                        state="ACTIVE"
                    elif re.search(r"is disabled|remains disabled|is no longer enabled|has stopped",detail,re.I):
                        state="DISABLED"
                    else:
                        continue
                    eligible.append({"rid":rid,"system":"integration_service","cat":"DATA_FLOW","state":state,
                                     "eid":str(event.get("activity_id") or ""),"file_ts":stamp,"obs_ts":stamp,
                                     "keys":set(),"data":event,"raw":detail,"path":"dataset/system_activity.csv"})
        risk={"PRESENT":5,"ACTIVE":5,"REDACTED":2,"ANONYMIZED":2,"DISABLED":1,"BLOCKED":1,"ABSENT":0}
        latest={}
        resource_categories=defaultdict(set)
        for o in sorted(eligible,key=lambda x:(x["obs_ts"],x["file_ts"],x["eid"])):
            key=(o["system"],o["rid"])
            resource_categories[key].add(o["cat"])
            prev=latest.get(key)
            if prev is None or (o["obs_ts"],o["file_ts"])>(prev["obs_ts"],prev["file_ts"]): latest[key]=o
            elif (o["obs_ts"],o["file_ts"])==(prev["obs_ts"],prev["file_ts"]) and risk.get(o["state"],3)>risk.get(prev["state"],3): latest[key]=o
        # A resource can be described by multiple event types across a log. Carry the
        # most specific identity-category classification forward to its latest state.
        for key,o in latest.items():
            if "SECONDARY_IDENTIFIER" in resource_categories.get(key,set()):
                o["cat"]="SECONDARY_IDENTIFIER"
        # Synthesize point-in-time absence only when a resource is explicitly linked to this identity
        # by activity and the newest applicable database/collection snapshot omits it.
        for rid in linked_resources:
            system=norm_system("",rid)
            cat=categorize({},system,rid,rid)
            matching=[c for c in self.coverage if c["file_ts"]<=cutoff and c["obs_ts"]<=cutoff and c["system"] in {"*",system} and c["cat"] in {"*",cat}]
            if not matching: continue
            groups=defaultdict(list)
            for c in matching: groups[(c["obs_ts"],c["file_ts"])].append(c)
            newest=max(groups)
            snapshot_rows=groups[newest]
            covered_ids=set().union(*(c["rids"] for c in snapshot_rows))
            if rid in covered_ids: continue
            previous=[o for o in self.observations if o["rid"]==rid and o["system"]==system and o["file_ts"]<=cutoff and o["obs_ts"]<=cutoff]
            latest_previous=max(((o["obs_ts"],o["file_ts"]) for o in previous),default=None)
            if latest_previous is not None and latest_previous>=newest: continue
            eid=sorted(c["eid"] for c in snapshot_rows)[0]
            latest[(system,rid)]={"rid":rid,"system":system,"cat":cat,"state":"ABSENT","eid":eid,
                "file_ts":newest[1],"obs_ts":newest[0],"keys":set(aliases),"data":{"resource_id":rid,"state":"ABSENT"},
                "raw":"resource absent from complete point-in-time snapshot","path":"derived from "+eid}
        return sorted(latest.values(),key=lambda o:(o["system"],o["rid"]))
