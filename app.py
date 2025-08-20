import streamlit as st
import jwt
import hmac, hashlib, json, time

# ------------------------
# Helper Functions
# ------------------------
def generate_jwt(payload, secret):
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_jwt(token, secret):
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        return True, decoded
    except Exception as e:
        return False, str(e)

def generate_hmac(message, secret):
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message, signature, secret):
    expected_sig = generate_hmac(message, secret)
    return hmac.compare_digest(expected_sig, signature)

# ------------------------
# Streamlit UI
# ------------------------
st.set_page_config(page_title="AWS x SAP Integration Demo", layout="centered")
st.title("AWS ↔ SAP Integration Demo (Simulated)")

st.sidebar.header("Demo Scenario")
scenario = st.sidebar.radio("Choose Scenario", ["AWS + SAP Integration"])

if scenario == "AWS + SAP Integration":
    st.subheader("Step 1–7: SAP → AWS Message Creation")

    # Step 1: Shared secret
    secret = st.text_input("Shared Secret (JWT & Signatures)", "demo-secret")

    # Step 2: Exchange mechanism
    exchange = st.selectbox("Exchange Mechanism", ["REST Push", "SFTP", "EventBridge"])

    # Step 3–5: Create Payload
    payload = {
        "sap_doc_id": "SAP12345",
        "timestamp": int(time.time()),
        "exchange": exchange,
        "data": {"customer": "ACME Corp", "amount": 5000, "currency": "USD"}
    }

    # Step 6: Generate JWT
    token = generate_jwt(payload, secret)

    # Step 7: Generate HMAC signature
    body_str = json.dumps(payload, indent=2)
    signature = generate_hmac(body_str, secret)

    st.code(f"JWT: {token}", language="bash")
    st.code(f"Signature: {signature}", language="bash")
    st.json(payload)

    st.divider()
    st.subheader("Step 8–13: AWS Validation")

    # Auto-fill values from SAP simulation
    jwt_input = st.text_area("Paste JWT", token)
    sig_input = st.text_area("Paste Signature", signature)
    body_input = st.text_area("Paste Body (JSON)", body_str)

    if st.button("Validate at AWS Layer"):
        # Validate JWT
        ok_jwt, decoded = verify_jwt(jwt_input, secret)

        # Validate HMAC
        ok_hmac = verify_hmac(body_input, sig_input, secret)

        if ok_jwt and ok_hmac:
            st.success("✅ Message Verified Successfully")
            st.json(decoded)
        else:
            st.error("❌ Verification Failed")
            st.write(f"JWT valid: {ok_jwt}, HMAC valid: {ok_hmac}")
