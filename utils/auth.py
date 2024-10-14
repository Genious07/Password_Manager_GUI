# utils/auth.py
import bcrypt
from utils.db import create_user, get_user

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(stored_hash, entered_password):
    return bcrypt.checkpw(entered_password.encode(), stored_hash)

def signup(username, password):
    existing_user = get_user(username)
    if existing_user:
        return False, "Username already exists."
    hashed_pw = hash_password(password)
    create_user(username, hashed_pw)
    return True, "User created successfully."

def login(username, password):
    user = get_user(username)
    if not user:
        return False, "Username does not exist."
    if verify_password(user['password'], password):
        return True, "Login successful.,Click Login again"
    else:
        return False, "Incorrect password."
