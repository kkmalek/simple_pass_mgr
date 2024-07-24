import json
import hashlib
import os
from cryptography.fernet import Fernet
from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this to a secure random value

# Function for Hashing the Master Password.
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

# Generate a secret key. This should be done only once as you'll see.
def generate_key():
    return Fernet.generate_key()

# Initialize Fernet cipher with the provided key.
def initialize_cipher(key):
    return Fernet(key)

# Function to encrypt a password.
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()

# Function to decrypt a password.
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# Function to register a user.
def register(username, master_password):
    hashed_master_password = hash_password(master_password)
    user_data = {'username': username, 'master_password': hashed_master_password}
    file_name = 'user_data.json'

    if not os.path.exists(file_name) or os.path.getsize(file_name) == 0:
        with open(file_name, 'w') as file:
            json.dump(user_data, file)
        return True
    return False

# Function to log in a user.
def login(username, entered_password):
    try:
        with open('user_data.json', 'r') as file:
            user_data = json.load(file)

        stored_password_hash = user_data.get('master_password')
        entered_password_hash = hash_password(entered_password)

        if entered_password_hash == stored_password_hash and username == user_data.get('username'):
            return True
        return False

    except Exception:
        return False

# Load or generate the encryption key.
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()
else:
    key = generate_key()
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)

cipher = initialize_cipher(key)

# Function to add (save) password.
def add_password(website, username, password):
    if not os.path.exists('passwords.json'):
        data = []
    else:
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []

    encrypted_password = encrypt_password(cipher, password)
    password_entry = {'website': website, 'username': username, 'password': encrypted_password}
    data.append(password_entry)

    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)

# Function to update (edit) password.
def update_password(index, website, username, password):
    if not os.path.exists('passwords.json'):
        return False

    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []

    if index < 0 or index >= len(data):
        return False

    encrypted_password = encrypt_password(cipher, password)
    data[index] = {'website': website, 'username': username, 'password': encrypted_password}

    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)

    return True

# Function to retrieve all saved passwords.
def get_all_passwords():
    if not os.path.exists('passwords.json'):
        return []

    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []

    passwords = []
    for index, entry in enumerate(data):
        decrypted_password = decrypt_password(cipher, entry['password'])
        passwords.append({'index': index, 'website': entry['website'], 'username': entry['username'], 'password': decrypted_password})

    return passwords

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['password']
        if register(username, master_password):
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login_user'))
        else:
            flash('User already registered.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['password']
        if login(username, master_password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login_user'))
    passwords = get_all_passwords()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'username' not in session:
        return redirect(url_for('login_user'))
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        add_password(website, username, password)
        flash('Password added!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add.html')

@app.route('/edit/<int:index>', methods=['GET', 'POST'])
def edit(index):
    if 'username' not in session:
        return redirect(url_for('login_user'))
    passwords = get_all_passwords()
    if index < 0 or index >= len(passwords):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        update_password(index, website, username, password)
        flash('Password updated!', 'success')
        return redirect(url_for('dashboard'))
    password = passwords[index]
    return render_template('edit.html', password=password)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
