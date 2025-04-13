

import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
import time
from datetime import datetime, timedelta

# Configuration
DATA_FILE = "secure_data.json"
USER_DB_FILE = "users.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds

# Generate or load encryption key
def get_encryption_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return open("secret.key", "rb").read()

KEY = get_encryption_key()
cipher = Fernet(KEY)

# Initialize or load data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def load_users():
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f)

stored_data = load_data()
user_db = load_users()

# Session state management
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = False
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Security functions
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    iterations = 100000  # High iteration count for PBKDF2
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode('utf-8'),
        salt.encode('utf-8'),
        iterations
    )
    return f"{salt}${iterations}${hashed.hex()}"

def verify_passkey(stored_hash, input_passkey):
    if stored_hash is None:
        return False
    salt, iterations, hashed = stored_hash.split('$')
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        input_passkey.encode('utf-8'),
        salt.encode('utf-8'),
        int(iterations)
    )
    return new_hash.hex() == hashed

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

def register_user(username, password):
    if username in user_db:
        return False, "Username already exists"
    
    hashed_pw = hash_passkey(password)
    user_db[username] = {
        "password_hash": hashed_pw,
        "created_at": str(datetime.now())
    }
    save_users(user_db)
    return True, "Registration successful"

def login_user(username, password):
    if username not in user_db:
        return False, "User not found"
    
    if verify_passkey(user_db[username]["password_hash"], password):
        st.session_state.authenticated = True
        st.session_state.current_user = username
        st.session_state.failed_attempts = 0
        return True, "Login successful"
    else:
        return False, "Incorrect password"

def logout():
    st.session_state.authenticated = False
    st.session_state.current_user = None
    st.session_state.failed_attempts = 0
    st.success("You have been successfully logged out.")

# Streamlit UI
st.title("🔒 Secure Data Encryption System")
st.write("created by sobiarao")

# Navigation menu
if st.session_state.authenticated:
    menu = ["Home", "Store Data", "Retrieve Data", "Account", "Logout"]
else:
    menu = ["Home", "Login", "Register"]

if st.session_state.locked_out:
    remaining_time = LOCKOUT_TIME - (time.time() - st.session_state.lockout_time)
    if remaining_time > 0:
        st.warning(f"🔒 System locked. Please try again in {int(remaining_time)} seconds.")
        choice = "Login"
    else:
        st.session_state.locked_out = False
        st.session_state.failed_attempts = 0
        choice = st.sidebar.selectbox("Navigation", menu)
else:
    choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("### Features:")
    st.write("- Secure encryption using Fernet (AES-128)")
    st.write("- PBKDF2 password hashing with salt")
    st.write("- Account lockout after 3 failed attempts")
    st.write("- Persistent data storage")
    st.write("- First, the user will register, and then they will be able to log in and access their account.")
    
    if st.session_state.authenticated:
        st.success(f"Logged in as: {st.session_state.current_user}")
        if st.button("Logout", key="logout_button_home"):
            logout()
            st.rerun()

elif choice == "Store Data" and st.session_state.authenticated:
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    data_id = st.text_input("Optional: Enter a unique identifier for your data:")

    if st.button("Encrypt & Save"):
        if not user_data:
            st.error("Please enter data to encrypt")
        elif not passkey:
            st.error("Please enter a passkey")
        elif passkey != confirm_passkey:
            st.error("Passkeys do not match!")
        else:
            if not data_id:
                data_id = f"{st.session_state.current_user}_{int(time.time())}"
            
            if data_id in stored_data:
                st.error("This ID already exists. Please choose a different one.")
            else:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data)
                stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "owner": st.session_state.current_user,
                    "timestamp": str(datetime.now())
                }
                save_data(stored_data)
                st.success(f"✅ Data stored securely with ID: {data_id}")

elif choice == "Retrieve Data" and st.session_state.authenticated:
    st.subheader("🔍 Retrieve Your Data")
    
    user_data_ids = [k for k, v in stored_data.items() if v.get("owner") == st.session_state.current_user]
    
    if not user_data_ids:
        st.warning("You have no stored data.")
    else:
        selected_id = st.selectbox("Select your data to retrieve:", user_data_ids)
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if not passkey:
                st.error("Please enter your passkey")
            else:
                data_entry = stored_data.get(selected_id)
                if data_entry and verify_passkey(data_entry["passkey"], passkey):
                    decrypted_text = decrypt_data(data_entry["encrypted_text"])
                    if decrypted_text:
                        st.success("✅ Decrypted Data:")
                        st.text_area("", decrypted_text, height=200)
                    else:
                        st.error("❌ Decryption failed!")
                else:
                    st.session_state.failed_attempts += 1
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {MAX_ATTEMPTS - st.session_state.failed_attempts}")

                    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                        st.session_state.locked_out = True
                        st.session_state.lockout_time = time.time()
                        st.warning("🔒 Too many failed attempts! System locked for 5 minutes.")
                        st.rerun()

elif choice == "Login":
    st.subheader("🔑 Login")
    
    if st.session_state.authenticated:
        st.success(f"You are already logged in as {st.session_state.current_user}")
        if st.button("Logout", key="logout_button_login"):
            logout()
            st.rerun()
    else:
        username = st.text_input("Username:")
        password = st.text_input("Password:", type="password")

        if st.button("Login"):
            success, message = login_user(username, password)
            if success:
                st.success(message)
                time.sleep(1)
                st.rerun()
            else:
                st.error(message)

elif choice == "Register":
    st.subheader("📝 Create New Account")
    
    if st.session_state.authenticated:
        st.warning("You are already logged in. Please logout to register a new account.")
    else:
        new_username = st.text_input("Choose a username:")
        new_password = st.text_input("Choose a password:", type="password")
        confirm_password = st.text_input("Confirm password:", type="password")

        if st.button("Register"):
            if not new_username or not new_password:
                st.error("Username and password are required")
            elif new_password != confirm_password:
                st.error("Passwords do not match!")
            else:
                success, message = register_user(new_username, new_password)
                if success:
                    st.success(message)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(message)

elif choice == "Account" and st.session_state.authenticated:
    st.subheader("👤 Account Information")
    st.write(f"Username: {st.session_state.current_user}")
    st.write(f"Registered on: {user_db[st.session_state.current_user]['created_at']}")
    
    if st.button("Change Password"):
        st.session_state.change_password = True
    
    if st.session_state.get('change_password'):
        current_pw = st.text_input("Current Password:", type="password")
        new_pw = st.text_input("New Password:", type="password")
        confirm_pw = st.text_input("Confirm New Password:", type="password")
        
        if st.button("Update Password"):
            if not verify_passkey(user_db[st.session_state.current_user]["password_hash"], current_pw):
                st.error("Current password is incorrect")
            elif new_pw != confirm_pw:
                st.error("New passwords don't match")
            else:
                user_db[st.session_state.current_user]["password_hash"] = hash_passkey(new_pw)
                save_users(user_db)
                st.success("Password updated successfully!")
                st.session_state.change_password = False
                st.rerun()
    
    if st.button("Logout", key="logout_button_account"):
        logout()
        st.rerun()

elif choice == "Logout":
    logout()
    st.rerun()

# Add logout button to sidebar if authenticated
if st.session_state.get('authenticated', False) and choice != "Logout":
    if st.sidebar.button("Logout", key="logout_button_sidebar"):
        logout()
        st.rerun()


