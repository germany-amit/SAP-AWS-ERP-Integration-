#!/usr/bin/env python3
# Smallest realistic SAP <-> AWS Integration MVP (13-step flow) - single file
# Run: pip install -r requirements.txt
#       streamlit run app.py

import os, json, time, hmac, hashlib, base64, uuid, random
from datetime import datetime, timedelta
import streamlit as st

st.set_page_config("SAP ↔ AWS Integration (Mini MVP)", layout="wide")

# -------------------------
# Helpers: JWT/HMAC, canonicalize, storage
# -------------------------
def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def json_canonical(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)

def sign_hmac(secret: str, msg: str) -> str:
    sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
    return b64url(sig)

def make_jwt(payload: dict, secret: str, ttl_sec: int = 300) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    p = dict(payload)
    p.update({"iat": now, "exp": now + ttl_sec})
    token = f"{b64url(json.dumps(header,separators=(',',':')).encode())}.{b64url(json.dumps(p,separators=(',',':')).encode())}"
    sig = sign_hmac(secret, token)
    return f"{token}.{sig}"

def verify_jwt(token: str, secret: str) -> (bool, str):
    try:
        head, body, sig = token.split(".")
        valid = sign_hmac(secret, f"{head}.{body}") == sig
        if not valid:
            return False, "Invalid signature"
        payload = json.loads(base64.urlsafe_b64decode(body + "==").decode())
        if int(time.time()) > payload.get("exp", 0):
            return False, "Token expired"
        return True, "OK"
    except Exception as e:
        return False, f"Malformed token: {e}"

# Simple local persistence (simulates S3/RDS/Queue)
DATA_DIR = "mvp_data"
os.makedirs(DATA_DIR, exist_ok=True)
SFTP_DIR = os.path.join(DATA_DIR, "sftp")
os.makedirs(SFTP_DIR, exist_ok=True)
QUEUE_FILE = os.path.join(DATA_DIR, "event_queue.json")
STORE_FILE = os.path.join(DATA_DIR, "store.json")

def push_queue(event):
    q = []
    if os.path.exists(QUEUE_FILE):
        try:
            q = json.load(open(QUEUE_FILE))
        except: q = []
    q.append(event)
    json.dump(q, open(QUEUE_FILE, "w"))

def pop_queue():
    if not os.path.exists(QUEUE_FILE): return None
    q = json.load(open(QUEUE_FILE))
    if not q: return None
    ev = q.pop(0)
    json.dump(q, open(QUEUE_FILE, "w"))
    return ev

def persist_store(key, obj):
    db = {}
    if os.path.exists(STORE_FILE):
        try: db = json.load(open(STORE_FILE))
        except: db = {}
    db[key] = obj
    json.dump(db, open(STORE_FILE, "w"))

def read_store():
    if not os.path.exists(STORE_FILE): return {}
    try: return json.load(open(STORE_FILE))
    except: return {}

# -------------------------
# UI: scenario and stepper
# -------------------------
st.title("SAP ↔ AWS Integration — Realistic Mini-MVP (13 steps)")

st.markdown("""
This app simulates a secure, production-like integration between SAP and AWS:
it generates signed payloads (SAP side), sends via REST/SFTP/Event queue (simulated),
validates & persists (AWS side), processes (Lambda simulation), returns acknowledgement,
and shows monitoring. Use the stepper controls below to run each step or auto-run all.
""")

secret = st.sidebar.text_input("Shared secret (pre-shared key)", value="demo-secret")
transport = st.sidebar.selectbox("Transport (simulate)", ["REST Push", "SFTP Batch", "Event (Queue)"])
auto_run = st.sidebar.checkbox("Auto-run all 13 steps sequentially", value=False)

# Step controls
step = st.sidebar.number_input("Step (manual control)", min_value=1, max_value=13, value=1, step=1)
run_step = st.sidebar.button("Run step")
run_all_btn = st.sidebar.button("Run all steps")

# Small helper to show timeline log
if "log" not in st.session_state: st.session_state.log = []
def log(msg):
    ts = datetime.utcnow().isoformat() + "Z"
    st.session_state.log.append(f"[{ts}] {msg}")
    # limit
    st.session_state.log = st.session_state.log[-200:]

# -------------------------
# 13-step implementations
# -------------------------
def step1_requirements_capture():
    st.subheader("Step 1 — Capture business requirements")
    st.write("Example: Reduce churn by 10% this year; send order events from SAP to cloud for analytics and retention.")
    reqs = st.text_area("Business requirements (editable)", value="Reduce churn 10%; real-time orders; PII safe; acks required; scale 10k/min")
    if st.button("Confirm requirements", key="s1"):
        log("Requirements confirmed")
        st.success("Requirements saved (simulated)")

def step2_identify_scope():
    st.subheader("Step 2 — Identify scope & data entities")
    st.write("Select entities that will be exchanged:")
    cols = st.columns(3)
    with cols[0]:
        cust = st.checkbox("Customer", value=True)
        order = st.checkbox("Order", value=True)
    with cols[1]:
        invoice = st.checkbox("Invoice", value=False)
        shipment = st.checkbox("Shipment", value=False)
    with cols[2]:
        churn = st.checkbox("ChurnSignal", value=True)
    entities = {"customer":cust, "order":order, "invoice":invoice, "shipment":shipment, "churn":churn}
    st.json(entities)
    if st.button("Save catalog", key="s2"):
        persist_store("entities", entities)
        log("Data entities catalog saved")
        st.success("Entity catalog persisted (local)")

def step3_choose_integration_pattern():
    st.subheader("Step 3 — Choose integration mechanism")
    st.write("Selected transport (left sidebar):", transport)
    st.info("REST Push = real-time; SFTP Batch = file-based batch; Event = async decoupled")
    if st.button("Confirm transport", key="s3"):
        persist_store("transport", transport)
        log(f"Transport confirmed: {transport}")
        st.success("Transport choice persisted")

def step4_prepare_payload_in_sap():
    st.subheader("Step 4 — SAP prepares payload")
    # realistic sample SAP order JSON
    sample = {
        "order_id": f"ORD-{uuid.uuid4().hex[:8]}",
        "customer_id": "CUST-1001",
        "amount": round(random.uniform(10, 1000), 2),
        "currency": "USD",
        "timestamp": datetime.utcnow().isoformat()+"Z",
        "items": [{"sku":"SKU-1","qty":2},{"sku":"SKU-2","qty":1}],
        "notes": "Sample SAP order"
    }
    st.code(json.dumps(sample, indent=2))
    if st.button("Save SAP payload (local)", key="s4"):
        persist_store("last_payload", sample)
        log(f"SAP payload prepared: {sample['order_id']}")
        st.success("Payload saved locally")

def step5_sign_and_attach_meta():
    st.subheader("Step 5 — Sign payload & attach metadata (idempotency, timestamp)")
    payload = read_store().get("last_payload")
    if not payload:
        st.warning("No payload present. Run step 4 first.")
        return
    idempotency_key = str(uuid.uuid4())
    canonical = json_canonical(payload)
    signature = sign_hmac(secret, canonical)
    jwt = make_jwt({"iss":"sap-system","sub":payload["order_id"]}, secret, ttl_sec=300)
    meta = {"idempotency": idempotency_key, "signature": signature, "jwt": jwt}
    st.json(meta)
    if st.button("Attach & persist signed message", key="s5"):
        msg = {"payload": payload, "meta": meta, "transport": transport}
        persist_store("outgoing_message", msg)
        log(f"Signed message created with idempotency {idempotency_key}")
        st.success("Signed message persisted (outgoing_message)")

def step6_send_to_transport():
    st.subheader("Step 6 — Send message via transport (simulated)")
    msg = read_store().get("outgoing_message")
    if not msg:
        st.warning("No outgoing message. Run step 5.")
        return
    if transport == "REST Push":
        # simulate HTTP POST by writing to a 'incoming' file
        incoming = {"headers":{"Authorization":f"Bearer {msg['meta']['jwt']}", "X-Signature": msg['meta']['signature'], "Idempotency": msg['meta']['idempotency']}, "body": msg['payload']}
        # simulate network transit delay
        time.sleep(0.3)
        persist_store("incoming_rest", incoming)
        log("Message pushed via simulated REST (incoming_rest)")
        st.success("Message pushed to simulated REST endpoint")
    elif transport == "SFTP Batch":
        # write to local SFTP dir as file
        fname = os.path.join(SFTP_DIR, f"{msg['payload']['order_id']}.json")
        with open(fname, "w") as f: json.dump({"meta": msg["meta"], "body": msg["payload"]}, f)
        log(f"Message placed on simulated SFTP: {fname}")
        st.success(f"File written to simulated SFTP: {fname}")
    else: # Event
        event = {"id":str(uuid.uuid4()), "meta":msg["meta"], "body":msg["payload"], "ts": datetime.utcnow().isoformat()+"Z"}
        push_queue(event)
        log(f"Event enqueued (queue file). Event id {event['id']}")
        st.success("Event pushed to simulated event queue")

def step7_aws_ingest_and_auth_validate():
    st.subheader("Step 7 — AWS Ingest: validate JWT & signature")
    ok = False
    reasons = []
    if transport == "REST Push":
        inc = read_store().get("incoming_rest")
        if not inc:
            st.warning("No incoming REST message. Run step 6")
            return
        jwt = inc["headers"].get("Authorization","").replace("Bearer ","")
        sig = inc["headers"].get("X-Signature","")
        body = inc["body"]
        valid_jwt, reason = verify_jwt(jwt, secret)
        if not valid_jwt: reasons.append("JWT failed: " + reason)
        else:
            # verify signature over canonical body
            if sign_hmac(secret, json_canonical(body)) != sig:
                reasons.append("Payload signature mismatch (canonicalization?)")
        if not reasons:
            ok = True
    elif transport == "SFTP Batch":
        files = os.listdir(SFTP_DIR)
        if not files:
            st.warning("No files on simulated SFTP. Run step 6")
            return
        # pick the first file
        fname = os.path.join(SFTP_DIR, files[0])
        doc = json.load(open(fname))
        jwt = doc["meta"]["jwt"]; sig = doc["meta"]["signature"]; body = doc["body"]
        valid_jwt, reason = verify_jwt(jwt, secret)
        if not valid_jwt: reasons.append("JWT failed: " + reason)
        else:
            if sign_hmac(secret, json_canonical(body)) != sig:
                reasons.append("Payload signature mismatch")
        if not reasons: ok = True
    else: # Event queue
        ev = pop_queue()
        if not ev:
            st.warning("Event queue empty. Run step 6")
            return
        jwt = ev["meta"]["jwt"]; sig = ev["meta"]["signature"]; body = ev["body"]
        valid_jwt, reason = verify_jwt(jwt, secret)
        if not valid_jwt: reasons.append("JWT failed: " + reason)
        else:
            if sign_hmac(secret, json_canonical(body)) != sig:
                reasons.append("Payload signature mismatch")
        if not reasons: ok = True
    if ok:
        st.success("Auth + signature validated. Message accepted for processing.")
        log("Auth & signature validated at AWS ingest")
        # persist incoming canonical
        incoming_record = {"received_at": datetime.utcnow().isoformat()+"Z", "body": body, "meta": {"jwt": jwt, "signature": sig}}
        persist_store("last_ingest", incoming_record)
    else:
        st.error("Validation failed: " + "; ".join(reasons))
        log("Validation failed: " + "; ".join(reasons))

def step8_schema_and_business_validation():
    st.subheader("Step 8 — Schema & business rule validation")
    rec = read_store().get("last_ingest")
    if not rec:
        st.warning("No ingested message. Run step 7")
        return
    body = rec["body"]
    # Simple schema checks
    required = ["order_id","customer_id","amount","timestamp"]
    missing = [r for r in required if r not in body]
    errors = []
    if missing:
        errors.append(f"Missing fields: {missing}")
    if body.get("amount",0) <= 0:
        errors.append("Amount must be > 0")
    # business check: suspicious order?
    suspicious = body.get("amount",0) > 900
    if errors:
        st.error("Schema/business validation errors: " + "; ".join(errors))
        log("Schema validation failed: " + "; ".join(errors))
    else:
        st.success("Schema and business rules passed")
        log("Schema validation passed")
        # persist to canonical store (simulate DB)
        key = f"order:{body['order_id']}"
        persist_store(key, {"body": body, "validated_at": datetime.utcnow().isoformat()+"Z", "suspicious": suspicious})
        st.info(f"Persisted canonical record under key {key}")

def step9_persist_and_enqueue_processing():
    st.subheader("Step 9 — Persist canonical record & enqueue for processing")
    rec = read_store()
    keys = [k for k in rec.keys() if k.startswith("order:")]
    if not keys:
        st.warning("No canonical order records. Run step 8")
        return
    key = keys[-1]
    st.json(read_store()[key])
    # simulate enqueue for ML scoring/processing
    proc_event = {"proc_id": str(uuid.uuid4()), "order_key": key, "ts": datetime.utcnow().isoformat()+"Z"}
    push_queue(proc_event)
    log(f"Enqueued processing event {proc_event['proc_id']} for {key}")
    st.success(f"Processing event enqueued ({proc_event['proc_id']})")

def step10_lambda_process_and_model_score():
    st.subheader("Step 10 — Lambda simulation: enrichment & model scoring")
    ev = pop_queue()
    if not ev:
        st.warning("No processing event in queue. Run step 9")
        return
    # if event is proc_event || model events could be in queue
    # fetch record
    key = ev.get("order_key")
    rec = read_store().get(key)
    if not rec:
        st.error("Referenced record not found")
        return
    body = rec["body"]
    # simple enrichment: attach risk score (fake model)
    score = round(min(1.0, random.random() * 0.6 + (body.get("amount",0)/1000)*0.4), 3)
    result = {"proc_id": ev.get("proc_id"), "score": score, "action_reco": "none" if score < 0.7 else "CSM outreach", "scored_at": datetime.utcnow().isoformat()+"Z"}
    # persist result
    persist_store(f"score:{ev.get('proc_id')}", result)
    log(f"Lambda processed {key} with score {score}")
    st.success(f"Processed and scored (score={score}). Result persisted.")

def step11_generate_acknowledgement_to_sap():
    st.subheader("Step 11 — Generate acknowledgement back to SAP (signed)")
    # find last score
    db = read_store()
    scores = [k for k in db.keys() if k.startswith("score:")]
    if not scores:
        st.warning("No score result. Run step 10")
        return
    key = scores[-1]
    result = db[key]
    ack = {"ack_id": str(uuid.uuid4()), "proc_id": result["proc_id"], "status": "processed", "score": result["score"], "ts": datetime.utcnow().isoformat()+"Z"}
    canonical = json_canonical(ack)
    sig = sign_hmac(secret, canonical)
    jwt = make_jwt({"iss":"aws-system","sub":ack["ack_id"]}, secret, ttl_sec=300)
    ack_msg = {"ack": ack, "meta": {"signature": sig, "jwt": jwt}}
    st.json(ack_msg)
    persist_store("outbound_ack", ack_msg)
    log(f"Acknowledgement generated {ack['ack_id']}")
    st.success("Acknowledgement generated and persisted (outbound_ack)")

def step12_send_ackback_to_sap():
    st.subheader("Step 12 — Send acknowledgement back to SAP (simulate transport)")
    ack = read_store().get("outbound_ack")
    if not ack:
        st.warning("No outbound ack. Run step 11")
        return
    # For simplicity, write to store 'sap_inbox' to simulate SAP receiving
    sap_inbox = read_store().get("sap_inbox", [])
    sap_inbox.append(ack)
    persist_store("sap_inbox", sap_inbox)
    log("Acknowledgement delivered to simulated SAP inbox")
    st.success("Ack delivered to simulated SAP inbox")

def step13_monitoring_and_alerts():
    st.subheader("Step 13 — Monitoring, metrics & drift alerts (simulated)")
    # generate small metrics snapshot
    metrics = {
        "ingest_rate_per_min": random.randint(10, 120),
        "p95_latency_ms": random.randint(50, 450),
        "error_rate_pct": round(random.uniform(0, 5), 2),
        "model_avg_score": round(random.uniform(0.45, 0.92), 3)
    }
    st.json(metrics)
    # simple alert rules
    alerts = []
    if metrics["p95_latency_ms"] > 300: alerts.append("High latency")
    if metrics["error_rate_pct"] > 2.5: alerts.append("High error rate")
    if metrics["model_avg_score"] < 0.5: alerts.append("Model performance degraded")
    if alerts:
        st.warning("Alerts: " + "; ".join(alerts))
        log("Alerts generated: " + "; ".join(alerts))
    else:
        st.success("No critical alerts")
        log("Monitoring ok")

# Mapping step numbers to functions
STEP_FN = {
    1: step1_requirements_capture,
    2: step2_identify_scope,
    3: step3_choose_integration_pattern,
    4: step4_prepare_payload_in_sap,
    5: step5_sign_and_attach_meta,
    6: step6_send_to_transport,
    7: step7_aws_ingest_and_auth_validate,
    8: step8_schema_and_business_validation,
    9: step9_persist_and_enqueue_processing,
    10: step10_lambda_process_and_model_score,
    11: step11_generate_acknowledgement_to_sap,
    12: step12_send_ackback_to_sap,
    13: step13_monitoring_and_alerts
}

# -------------------------
# Runner: manual or auto
# -------------------------
if auto_run or run_all_btn:
    st.info("Auto-running all 13 steps sequentially (pauses between steps to simulate processing)...")
    for i in range(1, 14):
        st.write(f"### Running step {i}")
        STEP_FN[i]()
        st.experimental_rerun()  # to update UI state after each step (note: stops loop after rerun)
else:
    # show the selected step
    st.write(f"### Selected Step: {step} / 13")
    STEP_FN[step]()
    if run_step:
        # re-run (simple trick: call again)
        st.experimental_rerun()

# -------------------------
# Log viewer & storage state
# -------------------------
st.sidebar.markdown("### Runtime Log")
for l in reversed(st.session_state.log[-30:]):
    st.sidebar.write(l)

st.sidebar.markdown("### Stored keys")
st.sidebar.write(list(read_store().keys())[:40])
