from flask import Flask, render_template, request, redirect, session, url_for
from tinydb import TinyDB, Query
from werkzeug.security import generate_password_hash, check_password_hash
from crypto_utils import feistel_encrypt, feistel_decrypt
import os
from datetime import datetime

from flask import Flask, render_template, request, redirect, session, url_for, flash
from tinydb import TinyDB, Query
from werkzeug.security import generate_password_hash, check_password_hash
import crypto_utils as crypto
import os, re, random

app = Flask(__name__)
app.secret_key = "mfa_secret_key"

db = TinyDB('database/db.json')
users_table = db.table('users')

# Email Validation Regex
def is_valid_email(email):
    return re.match(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$', email)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        
        if not is_valid_email(email):
            flash("Invalid Email Format!")
            return redirect(url_for('signup'))
            
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        users_table.insert({'username': username, 'email': email, 'password': hashed_pw, 'role': request.form['role']})
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = users_table.get(Query().username == request.form['username'])
        if user and check_password_hash(user['password'], request.form['password']):
            # STEP 1: Generate OTP for MFA
            otp = str(random.randint(100000, 999999))
            session['temp_user'] = user['username']
            session['temp_otp'] = otp
            print(f"DEBUG MFA: OTP for {user['username']} is {otp}") # In real life, send via email
            return redirect(url_for('verify_mfa'))
    return render_template('login.html')

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if request.method == 'POST':
        if request.form['otp'] == session.get('temp_otp'):
            session['username'] = session['temp_user']
            return redirect(url_for('index'))
    return render_template('verify_mfa.html')


app = Flask(__name__)
app.secret_key = "super_secret_session_key" 

# Initialize TinyDB
if not os.path.exists('database'):
    os.makedirs('database')

db = TinyDB('database/db.json')
users_table = db.table('users')
messages_table = db.table('messages')
audit_table = db.table('audit_logs')

# --- HELPER FUNCTIONS ---
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# --- GENERAL ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')


# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         role = request.form['role']
        
#         # Security: PBKDF2 Hashing
#         hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
#         users_table.insert({'username': username, 'password': hashed_pw, 'role': role})
        
#         audit_table.insert({
#             'user': username, 
#             'action': 'Account Created', 
#             'timestamp': get_timestamp()
#         })
#         return redirect(url_for('login'))
#     return render_template('signup.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        user_otp = request.form.get('otp')

        # Step 1: Check if Email is valid
        if not is_valid_email(email):
            return "<h3>Invalid Email Format!</h3><a href='/signup'>Try again</a>"

        # Step 2: Handle OTP Verification
        # If the user hasn't provided an OTP yet, generate one
        if not user_otp:
            generated_otp = str(random.randint(100000, 999999))
            session['reg_otp'] = generated_otp
            print(f"\n[SECURITY ALERT] OTP for {username}: {generated_otp}\n")
            # Usually, you'd render the same page with a flag to show the OTP field
            return render_template('signup.html', show_otp=True)

        # Step 3: Verify the OTP
        if user_otp == session.get('reg_otp'):
            # Clear OTP from session
            session.pop('reg_otp', None)
            
            # Hash password and save to DB
            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            users_table.insert({
                'username': username, 
                'email': email, 
                'password': hashed_pw, 
                'role': role
            })
            
            return redirect(url_for('login'))
        else:
            return "<h3>Incorrect OTP!</h3><a href='/signup'>Try again</a>"

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']
        
        User = Query()
        user = users_table.get(User.username == username)
        
        if user and check_password_hash(user['password'], password_candidate):
            session['username'] = username
            session['role'] = user['role']
            
            audit_table.insert({
                'user': username, 
                'action': 'Login Success', 
                'timestamp': get_timestamp()
            })
            
            if user['role'] == 'Admin': return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'Seller': return redirect(url_for('seller_dashboard'))
            else: return redirect(url_for('customer_dashboard'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        audit_table.insert({
            'user': session['username'], 
            'action': 'Logout', 
            'timestamp': get_timestamp()
        })
    session.clear()
    return redirect(url_for('index'))

# --- ADMIN ROUTES ---

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'Admin': return redirect(url_for('login'))
    user_count = len(users_table.all())
    msg_count = len(messages_table.all())
    return render_template('admin/dashboard.html', user_count=user_count, msg_count=msg_count)

@app.route('/admin/audit')
def admin_audit():
    if session.get('role') != 'Admin': return redirect(url_for('login'))
    logs = audit_table.all()
    return render_template('admin/audit.html', logs=logs)

@app.route('/admin/users')
def admin_users():
    if session.get('role') != 'Admin': return redirect(url_for('login'))
    users = users_table.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/keys')
def admin_keys():
    if session.get('role') != 'Admin': return redirect(url_for('login'))
    return render_template('admin/keys.html')

@app.route('/admin/settings')
def admin_settings():
    if session.get('role') != 'Admin': return redirect(url_for('login'))
    return render_template('admin/settings.html')

# --- SELLER ROUTES ---

@app.route('/seller/dashboard')
def seller_dashboard():
    if session.get('role') != 'Seller': return redirect(url_for('login'))
    return render_template('seller/dashboard.html')

@app.route('/seller/upload', methods=['GET', 'POST'])
def seller_upload():
    if session.get('role') != 'Seller': return redirect(url_for('login'))

    if request.method == 'POST':
        raw_message = request.form['message']
        # SYSTEM KEY for Feistel rounds
        system_key = "FEISTEL_KEY_2026" 
        encrypted_msg = feistel_encrypt(raw_message, system_key)
        
        messages_table.insert({
            'sender': session['username'],
            'encrypted_content': encrypted_msg,
            'timestamp': get_timestamp()
        })
        
        audit_table.insert({
            'user': session['username'],
            'action': 'Encrypted Submission Created',
            'timestamp': get_timestamp()
        })
        return redirect(url_for('seller_files'))

    return render_template('seller/upload.html')

@app.route('/seller/files')
def seller_files():
    if session.get('role') != 'Seller': return redirect(url_for('login'))
    all_messages = messages_table.all()
    # Map messages using their internal TinyDB doc_id
    msg_dict = {str(m.doc_id): m for m in all_messages}
    return render_template('seller/files.html', messages=msg_dict)


products_table = db.table('products')
@app.route('/seller/products', methods=['GET', 'POST'])
def seller_products():
    if session.get('role') != 'Seller': 
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get data from the form
        p_name = request.form.get('product_name')
        p_status = request.form.get('status')
        
        # Save to TinyDB
        products_table.insert({
            'name': p_name,
            'status': p_status,
            'seller': session['username']
        })
        return redirect(url_for('seller_products'))

    # GET request: Show the products
    all_products = products_table.all()
    return render_template('seller/products.html', products=all_products)
@app.route('/seller/messages')
def seller_messages():
    if session.get('role') != 'Seller': return redirect(url_for('login'))
    all_messages = messages_table.all()
    msg_dict = {str(m.doc_id): m for m in all_messages}
    return render_template('seller/messages.html', messages=msg_dict)

# --- CUSTOMER ROUTES ---

@app.route('/customer/dashboard')
def customer_dashboard():
    if session.get('role') != 'Customer': return redirect(url_for('login'))
    all_messages = messages_table.all()
    msg_dict = {str(m.doc_id): m for m in all_messages}
    return render_template('customer/dashboard.html', messages=msg_dict)

@app.route('/customer/files')
def customer_files():
    if session.get('role') != 'Customer': return redirect(url_for('login'))
    all_messages = messages_table.all()
    msg_dict = {str(m.doc_id): m for m in all_messages}
    return render_template('customer/files.html', messages=msg_dict)

@app.route('/customer/messages')
def customer_messages():
    if session.get('role') != 'Customer': return redirect(url_for('login'))
    all_messages = messages_table.all()
    msg_dict = {str(m.doc_id): m for m in all_messages}
    return render_template('customer/messages.html', messages=msg_dict)

@app.route('/customer/products')
def customer_products():
    if session.get('role') != 'Customer': 
        return redirect(url_for('login'))
    
    # IMPORTANT: Access the global products_table defined at the top of your script
    all_products = products_table.all() 
    
    # Pass the 'all_products' list to the template as 'products'
    return render_template('customer/products.html', products=all_products)

@app.route('/customer/decrypt/<msg_id>', methods=['GET', 'POST'])
def customer_decrypt(msg_id):
    if session.get('role') != 'Customer': return redirect(url_for('login'))

    # Fetch specific message using the TinyDB Document ID
    msg = messages_table.get(doc_id=int(msg_id))
    
    if not msg:
        return "Message record not found in vault.", 404

    encrypted_val = msg['encrypted_content']
    decrypted_msg = None
    error = None

    if request.method == 'POST':
        user_key = request.form['key']
        try:
            # INTEGRATING CRYPTOGRAPHY: Feistel Decryption
            decrypted_msg = feistel_decrypt(encrypted_val, user_key)
            
            audit_table.insert({
                'user': session['username'],
                'action': f'Successful Decryption (Record {msg_id})',
                'timestamp': get_timestamp()
            })
        except Exception as e:
            # Log exact error to console for debugging
            print(f"DEBUG: Decryption Error -> {e}")
            error = "Authentication Error: Incorrect Decryption Key."
            audit_table.insert({
                'user': session['username'],
                'action': f'Failed Decryption Attempt (Record {msg_id})',
                'timestamp': get_timestamp()
            })

    return render_template('customer/decrypt.html', encrypted_val=encrypted_val, decrypted_msg=decrypted_msg, error=error)

# --- EXECUTION ---
if __name__ == '__main__':
    app.run(debug=True)