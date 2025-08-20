# app.py — Compact World-Best MVP: AWS <-> SAP Integration + Architecture + Security + API + Monitoring
# Requirements: streamlit, PyJWT
# Run: pip install -r requirements.txt
#       streamlit run app.py

import streamlit as st, json, time, hmac, hashlib, uuid
import jwt, math, random

st.set_page_config("SAP↔AWS Integration — MVP", layout="wide")
st.title("🌐 AWS ↔ SAP Integration — Compact MVP")

# --------------------------- Sidebar ---------------------------
st.sidebar.title("Demo")
scenario = st.sidebar.radio("Choose", ["AWS + SAP Integration"], index=0)
st.sidebar.caption("Lightweight, free-tier, single-file demo")

# --------------------------- Session init ---------------------------
if "catalog" not in st.session_state: st.session_state.catalog = {}
if "registry" not in st.session_state: st.session_state.registry = {}
if "outgoing" not in st.session_state: st.session_state.outgoing = None
if "inbox" not in st.session_state: st.session_state.inbox = []
if "logs" not in st.session_state: st.session_state.logs = []

def log(msg):
    st.session_state.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}")
    if len(st.session_state.logs)>200: st.session_state.logs=st.session_state.logs[-200:]

# --------------------------- Tabs ---------------------------
tabs = st.tabs(["Overview / Arch", "Data Catalog", "SAP→AWS Flow (13)", "Security & EA", "APIs / OpenAPI", "Monitoring"])

# --------------------------- Tab: Architecture Designer ---------------------------
with tabs[0]:
    st.header("Design: End-to-End Architecture")
    req = st.text_area("Business Requirements", "Reduce churn 10%; real-time orders; PII safe", height=80)
    comps = st.multiselect("Components", ["SAP CPI/PI","API Gateway","Lambda","S3","RDS","EventBridge","SageMaker","SecretsManager"], default=["SAP CPI/PI","API Gateway","Lambda","S3","SageMaker"])
    prot = st.multiselect("Protocols", ["HTTPS/REST","JWT","mTLS","SFTP","Kafka","SQS/EventBridge"], default=["HTTPS/REST","JWT"])
    nfr = st.multiselect("NFRs", ["Scalable","Secure","Cost-Efficient","Resilient","Compliant"], default=["Scalable","Secure"])
    if st.button("Generate Architecture"):
        arch = {"requirements":req, "components":comps, "protocols":prot, "nfr":nfr, "flows":["SAP -> API Gateway -> Lambda -> S3/RDS -> SageMaker (optional)"]}
        st.json(arch)
        log("Architecture generated")
        st.success("Architecture artifact created — downloadable below")
        st.download_button("Download architecture.json", json.dumps(arch,indent=2), file_name="architecture.json")

# --------------------------- Tab: Data Catalog ---------------------------
with tabs[1]:
    st.header("Data Catalog & Business Mappings")
    with st.expander("Create / Update Entity"):
        en = st.text_input("Entity name", "Order")
        fields = st.text_area("Fields (one per line as name:type:is_pii)", "order_id:str:0\ncustomer_id:str:0\namount:float:0\nemail:str:1")
        if st.button("Save Entity"):
            f = []
            for line in [l.strip() for l in fields.splitlines() if l.strip()]:
                parts = line.split(":")
                f.append({"name":parts[0],"type":parts[1] if len(parts)>1 else "str","pii": bool(int(parts[2]) ) if len(parts)>2 else False})
            st.session_state.catalog[en]=f
            log(f"Entity saved: {en}")
            st.success(f"Saved entity {en}")
    if st.session_state.catalog:
        st.subheader("Catalog")
        for k,v in st.session_state.catalog.items():
            st.write("**%s**" % k); st.table(v)

# --------------------------- Tab: 13-step SAP → AWS Flow ---------------------------
with tabs[2]:
    st.header("SAP → AWS Integration (13 steps) — Simulated")
    secret = st.text_input("Shared secret (pre-shared key)", value="demo-secret", key="secret")
    transport = st.selectbox("Exchange mechanism", ["REST Push","SFTP Batch","EventBridge"], index=0)
    st.markdown("**Step 1-4**: SAP prepares payload & metadata")
    if st.button("Step 4: Prepare SAP payload"):
        payload = {
            "order_id": f"ORD-{uuid.uuid4().hex[:8]}",
            "customer": "ACME Corp",
            "amount": round(random.uniform(10,2000),2),
            "currency":"USD",
            "timestamp": int(time.time()),
            "transport": transport
        }
        st.session_state.outgoing = payload
        log(f"SAP payload prepared {payload['order_id']}")
        st.success("SAP payload prepared")
        st.json(payload)

    st.markdown("**Step 5: Sign & produce JWT + signature**")
    if st.button("Step 5: Sign message") and st.session_state.outgoing:
        payload = st.session_state.outgoing
        # canonicalize by sorted keys
        body = json.dumps(payload, separators=(',',':'), sort_keys=True)
        jwt_token = jwt.encode({"payload":payload,"iss":"sap-system","jti":str(uuid.uuid4())}, secret, algorithm="HS256")
        signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        msg = {"jwt":jwt_token,"signature":signature,"body":body}
        st.session_state.inbox.append(msg)  # simulate send to transport
        log(f"Message signed and sent; jti={json.loads(jwt.decode(jwt_token, options={'verify_signature': False}))['jti']}")
        st.success("Message signed & enqueued (simulated transport)")
        st.json({"jwt":jwt_token,"signature":signature,"body":payload})

    st.markdown("**Step 6-7**: Transport (simulated) — message sits in inbox; Step 8: AWS Ingest & Auth Validate")
    if st.button("Step 8: AWS validate next message") :
        if not st.session_state.inbox:
            st.warning("No message in simulated transport. Run Step 5 first.")
        else:
            msg = st.session_state.inbox.pop(0)
            try:
                decoded = jwt.decode(msg["jwt"], secret, algorithms=["HS256"])
                # verify body signature
                expected = hmac.new(secret.encode(), msg["body"].encode(), hashlib.sha256).hexdigest()
                if expected != msg["signature"]:
                    st.error("Signature mismatch — reject")
                    log("Validation failed: signature mismatch")
                else:
                    st.success("Auth & signature validated — accepted")
                    st.session_state.registry[decoded.get("jti","jti")] = {"payload":decoded["payload"], "received_at":int(time.time())}
                    log("Message accepted and persisted")
                    st.json(decoded)
            except Exception as e:
                st.error(f"JWT validation failed: {e}")
                log(f"Validation error: {e}")

    st.markdown("**Step 9-10**: Schema/business validation + enqueue for processing")
    if st.button("Step 9-10: Validate & enqueue processing"):
        # pick last persisted
        if not st.session_state.registry:
            st.warning("No persisted messages. Complete previous steps.")
        else:
            last = list(st.session_state.registry.items())[-1][1]
            body = last["payload"]
            errs=[]
            if "order_id" not in body: errs.append("missing order_id")
            if body.get("amount",0) <= 0: errs.append("amount<=0")
            if errs:
                st.error("Business validation failed: " + ";".join(errs)); log("Business validation failed")
            else:
                proc_id = str(uuid.uuid4())[:8]
                st.session_state.registry[f"proc_{proc_id}"] = {"status":"enqueued","payload":body}
                st.success("Enqueued for processing"); log(f"Enqueued processing {proc_id}")

    st.markdown("**Step 10-11**: Process (Lambda) + produce ack")
    if st.button("Step 10-11: Process & Ack"):
        procs = [k for k in st.session_state.registry.keys() if k.startswith("proc_")]
        if not procs:
            st.warning("No processing job found.")
        else:
            k = procs[-1]; rec = st.session_state.registry[k]
            score = round(min(1.0, random.random()*0.6 + rec["payload"].get("amount",0)/2000*0.4),3)
            ack = {"ack_id":str(uuid.uuid4())[:8],"order_id":rec["payload"]["order_id"],"status":"processed","score":score}
            # sign ack
            body = json.dumps(ack, separators=(',',':'), sort_keys=True)
            sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
            jwt_ack = jwt.encode({"ack":ack}, secret, algorithm="HS256")
            st.session_state.inbox.append({"jwt":jwt_ack,"signature":sig,"body":body})
            st.session_state.registry[k]["status"]="done"
            st.session_state.registry[k]["score"]=score
            st.success("Processed and ack generated & sent to SAP (simulated)")
            log(f"Processed job {k} score={score}")

    st.markdown("**Step 12-13**: SAP receives ack & Monitoring")
    if st.button("Step 12: SAP receive ack"):
        if not st.session_state.inbox:
            st.warning("No messages in transport")
        else:
            msg = st.session_state.inbox.pop(0)
            try:
                decoded = jwt.decode(msg["jwt"], secret, algorithms=["HS256"])
                expected = hmac.new(secret.encode(), msg["body"].encode(), hashlib.sha256).hexdigest()
                if expected==msg["signature"]:
                    st.success("SAP accepted ack")
                    st.json(decoded)
                    log("SAP accepted ack")
                else:
                    st.error("Ack signature mismatch"); log("Ack signature mismatch")
            except Exception as e:
                st.error(f"Ack JWT invalid: {e}"); log(f"Ack JWT invalid: {e}")

# --------------------------- Tab: Security & EA ---------------------------
with tabs[3]:
    st.header("Security, EA & Compliance")
    tls = st.checkbox("TLS (Transport) enforced", True)
    kms = st.checkbox("KMS / Key rotation", True)
    pii = st.checkbox("PII masked/minimized", True)
    iam = st.checkbox("Least-privilege IAM", True)
    audit = st.checkbox("Audit & Logging", True)
    score = int(100 * sum([tls,kms,pii,iam,audit]) / 5)
    st.metric("Compliance score", f"{score}%")
    st.markdown("**Recommendations:** Use Secrets Manager for keys, rotate keys, enable mTLS for partners when possible, enable CloudTrail & WAF.")

# --------------------------- Tab: APIs / OpenAPI ---------------------------
with tabs[4]:
    st.header("API Design & OpenAPI generator")
    base = st.text_input("Base path", "/v1")
    resources = st.multiselect("Resources", ["orders","customers","churn"], default=["orders","churn"])
    rate = st.number_input("Rate limit (rpm)", 60, 6000, 300)
    if st.button("Generate OpenAPI"):
        paths={}
        for r in resources:
            paths[f"{base}/{r}"] = {"get":{"summary":f"List {r}","responses":{"200":{"description":"OK"}}},"post":{"summary":f"Create {r[:-1]}","responses":{"201":{"description":"Created"}}}}
        oas={"openapi":"3.0.0","info":{"title":"Demo API","version":"1.0.0"},"x-rate-limit":rate,"paths":paths}
        st.json(oas)
        st.download_button("Download openapi.json", json.dumps(oas,indent=2), file_name="openapi.json")
        log("OpenAPI generated")

# --------------------------- Tab: Monitoring ---------------------------
with tabs[5]:
    st.header("Monitoring & Impact Assessor")
    # simple simulated timeseries
    minutes = list(range(60))
    p95 = [120 + 30*math.sin(m/6) + random.gauss(0,6) for m in minutes]
    err = [max(0, random.gauss(1.5,0.7)) for _ in minutes]
    st.line_chart({"p95_ms":p95,"error_rate_pct":err})
    st.markdown("**Impact Assessor (change a contract → see impacted components)**")
    change = st.selectbox("Proposed change", ["none","change_order_schema","remove_idempotency","increase_jwt_ttl"])
    if st.button("Assess impact"):
        mapping = {
            "change_order_schema":["API Gateway","Lambda(order-processor)","Downstream analytics","Integration tests"],
            "remove_idempotency":["Duplicates, Database inconsistencies, Retry logic"],
            "increase_jwt_ttl":["Longer replay window → increase risk; require replay detection"]
        }
        st.json(mapping.get(change, ["No impact"]))
        log(f"Impact assessed: {change}")

# --------------------------- Footer: logs ---------------------------
st.sidebar.header("Runtime log")
for l in st.session_state.logs[-15:][::-1]:
    st.sidebar.write(l)
