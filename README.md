🔐 Password Manager App
A simple, secure, and easy-to-use password manager app built with Streamlit and MongoDB. This app allows users to securely store, manage, and retrieve their passwords in an encrypted format. Users can sign up, log in, add passwords, view existing passwords, edit them, delete them, and change their login password.

Features
User Authentication: Secure sign-up and login functionality using hashed passwords.
Password Encryption: All stored passwords are encrypted using Fernet encryption before saving to the database.
CRUD Operations: Users can add, view, edit, and delete passwords.
Change Password: Users can change their login password securely.
MongoDB Integration: User data and passwords are stored in MongoDB for scalability.
Responsive UI: Built with Streamlit, providing a simple and interactive user interface.

Technologies Used
Python
Streamlit: For building the user interface.
MongoDB: For storing user credentials and passwords.
Cryptography (Fernet): For encrypting and decrypting passwords.
bcrypt: For hashing and verifying user passwords.
dotenv: For securely managing environment variables.

PROJECT STRUCTURE 
password_manager_app/
├── app.py                 # Main application
├── requirements.txt        # Dependencies
├── .env                    # Environment variables
└── utils/                  # Utility modules
    ├── auth.py             # Handles user authentication (signup, login)
    ├── db.py               # Handles database operations (CRUD)
    └── encryption.py       # Encrypts and decrypts passwords

Getting Started
Follow these steps to run the project on your local machine:

Prerequisites
Ensure you have the following installed:

Python 3.8+
MongoDB (Running locally or in the cloud)
Pip (Python package installer)


Installation
Clone the Repository:
git clone https://github.com/your-username/password_manager_app.git
cd password_manager_app


Create a Virtual Environment (optional but recommended):
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`


Install Dependencies:
pip install -r requirements.txt

Set Up Environment Variables:
Create a .env file in the root of the project directory with the following variables:
MONGO_URI=your_mongo_connection_string
ENCRYPTION_KEY=your_generated_encryption_key

MONGO_URI: Your MongoDB connection string.

ENCRYPTION_KEY: A 32-byte URL-safe base64-encoded key for encryption. You can generate one using the following Python code:
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print(key.decode())


Run the Application:
streamlit run app.py

This command will start the app locally. Open your browser and navigate to http://localhost:8501.

MongoDB Setup
Local MongoDB: If running MongoDB locally, ensure that your MongoDB server is running. You can use mongodb://localhost:27017/ as your MONGO_URI in the .env file.

MongoDB Atlas: If using MongoDB Atlas, create a cluster, obtain your connection string, and use it in your MONGO_URI.

Encryption Key
The ENCRYPTION_KEY is essential for encrypting and decrypting passwords. Ensure that this key remains secret and secure, as losing it will prevent decryption of stored passwords.


Usage
Sign Up: Create a new user account.
Login: Use your credentials to log in.
Add Passwords: Securely add passwords for your accounts (e.g., Gmail, Facebook).
View Passwords: View your saved passwords (they will be decrypted and displayed).
Edit/Delete Passwords: Modify or remove saved passwords.
Change Login Password: Update your login password.


Future Improvements
Two-Factor Authentication (2FA) for additional security.
Password Strength Checker to encourage strong password creation.
Password Export: Option to export saved passwords securely.
Session Timeout: Automatic logout after a period of inactivity.

Contributing
Pull requests are welcome! If you'd like to contribute, please fork the repository and make your changes. Submit a pull request for review.
