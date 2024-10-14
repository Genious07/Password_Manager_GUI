# utils/db.py
import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI not found in environment variables.")

client = MongoClient(MONGO_URI)
db = client['password_manager']
users_collection = db['users']
passwords_collection = db['passwords']

def create_user(username, hashed_password):
    user = {
        "username": username,
        "password": hashed_password
    }
    users_collection.insert_one(user)

def get_user(username):
    return users_collection.find_one({"username": username})

def add_password_entry(username, account, acc_username, acc_password):
    entry = {
        "username": username,
        "account": account,
        "account_username": acc_username,
        "account_password": acc_password
    }
    passwords_collection.insert_one(entry)

def get_password_entries(username):
    return list(passwords_collection.find({"username": username}))

def update_password_entry(username, account, new_acc_password):
    passwords_collection.update_one(
        {"username": username, "account": account},
        {"$set": {"account_password": new_acc_password}}
    )

def delete_password_entry(username, account):
    passwords_collection.delete_one({"username": username, "account": account})

def update_user_password(username, new_hashed_password):
    users_collection.update_one(
        {"username": username},
        {"$set": {"password": new_hashed_password}}
    )
