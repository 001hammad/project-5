import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# Generate/load encryption key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

with open("secret.key", "rb") as key_file:
    KEY = key_file.read()

cipher = Fernet(KEY)

# JSON file for users and data
DATA_FILE = "data_store.json"

# Load existing data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as file:
        stored_data = json.load(file)
else:
    stored_data = {"users": {}, "data": {}}

# Helper functions
def save_data():
    with open(DATA_FILE, "w") as file:
        json.dump(stored_data, file)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Streamlit App
st.title("🔐 Secure Data Vault")

menu = [ "Register", "Login", "Store Data", "Retrieve Data", "Delete My Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

# Home
if choice == "Home":
    st.markdown("## 👋 Welcome to Secure Data Vault")
    st.info("Please register or log in to store and retrieve your data securely.")

# Register
elif choice == "Register":
    st.subheader("📝 Register New Account")
    name = st.text_input("Name")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Register"):
        if username in stored_data["users"]:
            st.error("🚫 Username already exists.")
        elif not (name and username and password):
            st.error("⚠️ All fields are required.")
        else:
            stored_data["users"][username] = {
                "name": name,
                "password": hash_password(password)
            }
            save_data()
            st.success("✅ Registered successfully! You can now log in.")

# Login
elif choice == "Login":
    st.subheader("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = stored_data["users"].get(username)
        if user and hash_password(password) == user["password"]:
            st.session_state.logged_in_user = username
            st.success(f"✅ Welcome {user['name']}! You are now logged in.")
        else:
            st.error("❌ Invalid credentials.")

# Store Data
elif choice == "Store Data":
    if not st.session_state.logged_in_user:
        st.warning("🚫 Please log in first.")
    else:
        st.subheader("📥 Store Encrypted Data")
        unique_id = st.text_input("Enter Unique ID:")
        plain_text = st.text_area("Enter Data to Encrypt:")

        if st.button("Encrypt & Store"):
            if unique_id and plain_text:
                encrypted = encrypt_data(plain_text)
                stored_data["data"][unique_id] = {
                    "owner": st.session_state.logged_in_user,
                    "encrypted": encrypted
                }
                save_data()
                st.success("✅ Data encrypted and saved successfully.")
            else:
                st.error("⚠️ Both fields are required.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.logged_in_user:
        st.warning("🚫 Please log in first.")
    else:
        st.subheader("📤 Retrieve Decrypted Data")
        unique_id = st.text_input("Enter Unique ID to Retrieve:")

        if st.button("Decrypt"):
            record = stored_data["data"].get(unique_id)
            if record:
                if record["owner"] == st.session_state.logged_in_user:
                    decrypted = decrypt_data(record["encrypted"])
                    st.success(f"✅ Decrypted Data: {decrypted}")
                else:
                    st.error("🚫 You don't have access to this data.")
            else:
                st.error("❌ No data found for this ID.")

# Delete Data
elif choice == "Delete My Data":
    if not st.session_state.logged_in_user:
        st.warning("🚫 Please log in first to delete your data.")
    else:
        with st.container():
            st.markdown("### 🗑️ Delete Encrypted Data")
            unique_id = st.text_input("Enter Unique ID to Delete")

            if st.button("Delete"):
                record = stored_data["data"].get(unique_id)
                if record:
                    if record["owner"] == st.session_state.logged_in_user:
                        del stored_data["data"][unique_id]
                        save_data()
                        st.success(f"✅ Data with ID '{unique_id}' has been deleted.")
                    else:
                        st.error("🚫 You don't have permission to delete this data.")
                else:
                    st.error("❌ No data found with this ID.")
