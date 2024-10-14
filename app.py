# app.py
import streamlit as st
from utils.auth import signup, login
from utils.db import (
    add_password_entry,
    get_password_entries,
    update_password_entry,
    delete_password_entry,
    update_user_password,
    get_user
)
from utils.encryption import encrypt_password, decrypt_password
import bcrypt

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ''
    st.session_state.current_page = 'login'  # 'login', 'signup', 'dashboard'

def login_page():
    st.title("Password Manager - Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type='password', key="login_password")
    if st.button("Login"):
        if not username or not password:
            st.error("Please enter both username and password.")
        else:
            success, message = login(username, password)
            if success:
                st.success(message)
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.current_page = 'dashboard'
            else:
                st.error(message)
    st.write("---")
    st.subheader("Don't have an account?")
    if st.button("Sign Up"):
        st.session_state.current_page = 'signup'

def signup_page():
    st.title("Password Manager - Sign Up")
    username = st.text_input("Choose a Username", key="signup_username")
    password = st.text_input("Choose a Password", type='password', key="signup_password")
    confirm_password = st.text_input("Confirm Password", type='password', key="signup_confirm_password")
    if st.button("Sign Up"):
        if not username or not password or not confirm_password:
            st.error("Please fill out all fields.")
        elif password != confirm_password:
            st.error("Passwords do not match.")
        else:
            success, message = signup(username, password)
            if success:
                st.success(message)
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.current_page = 'dashboard'
            else:
                st.error(message)
    st.write("---")
    st.subheader("Already have an account?")
    if st.button("Back to Login"):
        st.session_state.current_page = 'login'

def dashboard():
    st.title("Your Passwords")
    st.sidebar.header(f"Logged in as {st.session_state.username}")
    task = st.sidebar.selectbox("Select Task", ["Add Password", "View Passwords", "Edit Password", "Delete Password", "Change Password", "Logout"])

    if task == "Add Password":
        st.subheader("Add a New Password")
        with st.form("add_password_form"):
            account = st.text_input("Account Name")
            acc_username = st.text_input("Account Username")
            acc_password = st.text_input("Account Password", type='password')
            submit_add = st.form_submit_button("Add")
            if submit_add:
                if account and acc_username and acc_password:
                    encrypted_pw = encrypt_password(acc_password)
                    add_password_entry(st.session_state.username, account, acc_username, encrypted_pw)
                    st.success("Password added successfully.")
                else:
                    st.error("Please fill out all fields.")

    elif task == "View Passwords":
        st.subheader("Your Saved Passwords")
        entries = get_password_entries(st.session_state.username)
        if entries:
            for entry in entries:
                with st.expander(entry['account']):
                    st.write(f"**Username:** {entry['account_username']}")
                    decrypted_pw = decrypt_password(entry['account_password'])
                    st.write(f"**Password:** {decrypted_pw}")
        else:
            st.info("No passwords saved yet.")

    elif task == "Edit Password":
        st.subheader("Edit an Existing Password")
        entries = get_password_entries(st.session_state.username)
        if entries:
            accounts = [entry['account'] for entry in entries]
            selected_account = st.selectbox("Select Account to Edit", accounts, key="edit_select_account")
            new_password = st.text_input("New Password", type='password', key="edit_new_password")
            if st.button("Update"):
                if selected_account and new_password:
                    encrypted_pw = encrypt_password(new_password)
                    update_password_entry(st.session_state.username, selected_account, encrypted_pw)
                    st.success("Password updated successfully.")
                else:
                    st.error("Please select an account and enter a new password.")
        else:
            st.info("No passwords available to edit.")

    elif task == "Delete Password":
        st.subheader("Delete a Password Entry")
        entries = get_password_entries(st.session_state.username)
        if entries:
            accounts = [entry['account'] for entry in entries]
            selected_account = st.selectbox("Select Account to Delete", accounts, key="delete_select_account")
            if st.button("Delete"):
                if selected_account:
                    delete_password_entry(st.session_state.username, selected_account)
                    st.success("Password deleted successfully.")
                else:
                    st.error("Please select an account to delete.")
        else:
            st.info("No passwords available to delete.")

    elif task == "Change Password":
        st.subheader("Change Your Login Password")
        with st.form("change_password_form"):
            current_password = st.text_input("Current Password", type='password')
            new_password = st.text_input("New Password", type='password')
            confirm_new_password = st.text_input("Confirm New Password", type='password')
            submit_change = st.form_submit_button("Change Password")
            if submit_change:
                if not current_password or not new_password or not confirm_new_password:
                    st.error("Please fill out all fields.")
                elif new_password != confirm_new_password:
                    st.error("New passwords do not match.")
                else:
                    user = get_user(st.session_state.username)
                    if user and bcrypt.checkpw(current_password.encode(), user['password']):
                        new_hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                        update_user_password(st.session_state.username, new_hashed_pw)
                        st.success("Password changed successfully.")
                    else:
                        st.error("Current password is incorrect.")
    
    elif task == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ''
        st.session_state.current_page = 'login'
        st.success("Logged out successfully.")

def main():
    if st.session_state.get('logged_in'):
        st.session_state.current_page = 'dashboard'
    
    if st.session_state.get('current_page') == 'login':
        login_page()
    elif st.session_state.get('current_page') == 'signup':
        signup_page()
    elif st.session_state.get('current_page') == 'dashboard':
        dashboard()
    else:
        # Default to login page if current_page is not set correctly
        st.session_state.current_page = 'login'
        login_page()

if __name__ == "__main__":
    main()
