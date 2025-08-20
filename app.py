import streamlit as st
import jwt
import datetime
import json
import hashlib

st.set_page_config(page_title="AWS + SAP Integration MVP", layout="wide")

st.title("🌍 AWS + SAP Integration - 13 Step Demo")
st.write("This is a minimal running demo that simulates how **SAP ↔ AWS integration** works securely.")

# --------------------------------------------
# Session state initialization
# --------------------------------------------
if "signed_message" not in st.session_state:
    st.session_state["signed_message"] = None


# --------------------------------------------
# Step 1-4: Choose Integration Setup
# --------------------------------------------
st.header("🔑 Step 1-4: Setup Integration")

secret_key = st.text_input("Shared Secret (for JWT & signature)", value="my_shared_secret")
exchange_mode = st.radio(
    "Choose Exchange Mechanism",
    ["REST Push", "SFTP", "EventBridge"],
    index=0
)


# --------------------------------------------
# Step 5-8: Create Payload in SAP
# --------------------------------------------
st.header("📦 Step 5-8: Prepare Payload (SAP Side)")

payload = st.text_area("Enter SAP Payload (JSON)", value='{"order_id": 123, "amount": 5000, "currency": "USD"}')

if st.button("Sign & Send (SAP → AWS)"):
    try:
        # Create JWT
        jwt_token = jwt.encode(
            {"payload": payload, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)},
            secret_key,
            algorithm="HS256"
        )
        # Create Signature
        signature = hashlib.sha256((payload + secret_key).encode()).hexdigest()

        # Save in session
        st.session_state["signed_message"] = {
            "payload": payload,
            "jwt": jwt_token,
            "signature": signature,
            "mode": exchange_mode
        }

        st.success("✅ Message signed and sent successfully!")
        st.json(st.session_state["signed_message"])

    except Exception as e:
        st.error(f"Error creating signed message: {e}")


# --------------------------------------------
# Step 9-13: Validate on AWS Side
# --------------------------------------------
st.header("🛡️ Step 9-13: Validate Message (AWS Side)")

if st.session_state["signed_message"]:
    sm = st.session_state["signed_message"]

    jwt_input = st.text_area("Paste JWT", value=sm["jwt"])
    signature_input = st.text_input("Paste Signature", value=sm["signature"])
    payload_input = st.text_area("Paste Payload", value=sm["payload"])

    if st.button("Validate on AWS"):
        try:
            # Validate JWT
            decoded = jwt.decode(jwt_input, secret_key, algorithms=["HS256"])
            # Validate signature
            expected_sig = hashlib.sha256((payload_input + secret_key).encode()).hexdigest()

            if signature_input == expected_sig:
                st.success("✅ Validation successful! Message is authentic and secure.")
                st.json({"Decoded JWT": decoded, "Exchange Mode": sm["mode"]})
            else:
                st.error("❌ Signature mismatch. Message may be tampered.")
        except Exception as e:
            st.error(f"JWT validation failed: {e}")
else:
    st.info("👉 First, sign & send a message from SAP side above.")
