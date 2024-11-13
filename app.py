from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
import mimetypes
from pdf2image import convert_from_bytes
from flask_migrate import Migrate
import hashlib
import binascii 


app = Flask(__name__)
app.secret_key = 'secret_key_for_sessions'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

migrate = Migrate(app, db)  # Add this line

# Models for users and files
# Models for users and files
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    files = db.relationship('File', backref='owner')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filesize = db.Column(db.Integer, nullable=False)
    encryption_method = db.Column(db.String(50), nullable=False)  # Add this


# Home route (index)
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect('/dashboard')
    if 'admin' in session:
        return redirect('/admin_dashboard')
    return render_template('index.html')


# Route for registration
# Registration route with password length validation
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Ensure password is exactly 8 characters
        if len(password) != 8:
            flash('Password must be exactly 8 characters long!', 'danger')
            return redirect('/register')

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists! Please try another.', 'danger')
            return redirect('/register')

        # Hash password and save the user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful, please log in.', 'success')
        return redirect('/login')

    return render_template('register.html')

# Function to generate a key of desired size (AES: 32, DES: 8 bytes)
def generate_key_from_password(password, key_length):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed[:key_length]

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user is None:
            flash('User not found, please sign up first.', 'danger')
            return redirect('/login')

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect('/dashboard')
        else:
            flash('Invalid username or password!', 'danger')
    return render_template('login.html')


# User dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        files = File.query.filter_by(user_id=user.id).all()
        return render_template('user_dashboard.html', files=files)
    flash('Please log in to access the dashboard.', 'warning')
    return redirect('/login')



    if 'user_id' in session:
        file = db.session.get(File, file_id)
        if file and file.user_id == session['user_id']:
            user = db.session.get(User, session['user_id'])
            key = user.password[:32].encode()
            
            # Decrypt the file data
            with open(file.filepath, 'rb') as f:
                encrypted_file_data = f.read()
            decrypted_file_data = decrypt_file_aes(key, encrypted_file_data)
            
            # Check if it's a PDF
            file_type, _ = mimetypes.guess_type(file.filename)
            if file_type == 'application/pdf':
                return send_file(
                    BytesIO(decrypted_file_data),
                    mimetype='application/pdf',
                    as_attachment=False,
                    download_name=file.filename
                )
            
            # Handle other file types (image, etc.) here
    flash('Unauthorized access to the file.', 'danger')
    return redirect('/dashboard')



def create_preview(file_type, file_data, file_info):
    try:
        if file_type and file_type.startswith('image/'):
            return create_image_preview(file_data)
        elif file_type == 'application/pdf':
            return create_pdf_preview(file_data)
        else:
            return create_text_preview(file_info)
    except Exception as e:
        print(f"Error creating preview: {e}")
        return create_text_preview(file_info)


def create_image_preview(file_data):
    img = Image.open(BytesIO(file_data))
    img.thumbnail((300, 300))
    return img

def create_pdf_preview(file_data):
    images = convert_from_bytes(file_data, first_page=1, last_page=1)
    if images:
        preview = images[0]
        preview.thumbnail((300, 300))
        return preview
    raise Exception("Failed to convert PDF to image")

def create_text_preview(file_info):
    preview_image = Image.new('RGB', (300, 200), color='white')
    draw = ImageDraw.Draw(preview_image)
    font = ImageFont.load_default()
    
    draw.text((10, 10), f"File: {file_info.filename}", fill="black", font=font)
    draw.text((10, 30), f"Size: {file_info.filesize} bytes", fill="black", font=font)
    draw.text((10, 50), f"Type: {mimetypes.guess_type(file_info.filename)[0] or 'Unknown'}", fill="black", font=font)
    draw.text((10, 70), "Content preview not available", fill="black", font=font)
    
    return preview_image

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' in session:
        if request.method == 'POST':
            user = db.session.get(User, session['user_id'])
            file = request.files['file']
            filename = file.filename
            file_data = file.read()

            # Get selected encryption method
            encryption_method = request.form.get('encryption_method', 'aes')  # Default to 'aes' if not specified

            try:
                if encryption_method == 'aes':
                    key = generate_key_from_password(user.password, 32)  # 32-char hex for AES
                    encrypted_file_data = encrypt_file_aes(key, file_data)
                elif encryption_method == 'des':
                    key = generate_key_from_password(user.password, 16)  # 16-char hex for DES
                    encrypted_file_data = encrypt_file_des(key, file_data)
                else:
                    raise ValueError("Unsupported encryption method.")

                # Save encrypted file
                filepath = os.path.join('storage', f"{filename}.enc")
                os.makedirs('storage', exist_ok=True)

                with open(filepath, 'wb') as f:
                    f.write(encrypted_file_data)

                # Store file metadata in the database
                new_file = File(
                    filename=filename,
                    filepath=filepath,
                    user_id=user.id,
                    filesize=len(encrypted_file_data),
                    encryption_method=encryption_method
                )
                db.session.add(new_file)
                db.session.commit()

                flash('File uploaded and encrypted successfully!', 'success')
                return redirect('/dashboard')

            except Exception as e:
                db.session.rollback()
                flash(f'Error during upload: {str(e)}', 'danger')
                return redirect('/upload')

        return render_template('upload.html')
    return redirect('/login')

@app.route('/view/<int:file_id>')
def view_file(file_id):
    if 'user_id' in session:
        file = File.query.get(file_id)
        if file and file.user_id == session['user_id']:
            user = User.query.get(session['user_id'])
            
            try:
                # Read the encrypted file
                with open(file.filepath, 'rb') as f:
                    encrypted_file_data = f.read()

                # Decrypt based on encryption method
                if file.encryption_method == 'aes':
                    key = generate_key_from_password(user.password, 32)
                    decrypted_file_data = decrypt_file_aes(key, encrypted_file_data)
                elif file.encryption_method == 'des':
                    key = generate_key_from_password(user.password, 16)
                    decrypted_file_data = decrypt_file_des(key, encrypted_file_data)
                else:
                    raise ValueError("Unsupported encryption method")

                # Return the file for viewing
                return send_file(
                    BytesIO(decrypted_file_data),
                    mimetype=mimetypes.guess_type(file.filename)[0] or 'application/octet-stream',
                    as_attachment=False,
                    download_name=file.filename
                )
            except Exception as e:
                flash(f'Error viewing file: {str(e)}', 'danger')
                return redirect('/dashboard')

    flash('Unauthorized access to the file.', 'danger')
    return redirect('/dashboard')


@app.route('/delete_file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' in session:
        file = db.session.get(File, file_id)
        if file and file.user_id == session['user_id']:
            # Delete the physical file
            if os.path.exists(file.filepath):
                os.remove(file.filepath)
            
            # Delete the database entry
            db.session.delete(file)
            db.session.commit()
            
            flash('File deleted successfully!', 'success')
        else:
            flash('File not found or you do not have permission to delete it.', 'danger')
    else:
        flash('Please log in to delete files.', 'warning')
    return redirect('/dashboard')



# Download route that handles decryption based on the stored encryption method
# Download route with decryption based on the encryption method
@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' in session:
        file = File.query.get(file_id)
        if file and file.user_id == session['user_id']:
            user = User.query.get(session['user_id'])
            
            try:
                # Read the encrypted file
                with open(file.filepath, 'rb') as f:
                    encrypted_file_data = f.read()

                # Decrypt based on encryption method
                if file.encryption_method == 'aes':
                    key = generate_key_from_password(user.password, 32)
                    decrypted_file_data = decrypt_file_aes(key, encrypted_file_data)
                elif file.encryption_method == 'des':
                    key = generate_key_from_password(user.password, 16)
                    decrypted_file_data = decrypt_file_des(key, encrypted_file_data)
                else:
                    raise ValueError("Unsupported encryption method")

                # Return the decrypted file
                return send_file(
                    BytesIO(decrypted_file_data),
                    mimetype='application/octet-stream',
                    as_attachment=True,
                    download_name=file.filename
                )
            except Exception as e:
                flash(f'Error decrypting file: {str(e)}', 'danger')
                return redirect('/dashboard')

    flash('Unauthorized access to the file.', 'danger')
    return redirect('/dashboard')

# Route for Admin login
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if 'admin' in session:
        flash('You are already logged in as admin.', 'info')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin' and password == 'adminpass123':
            session['admin'] = True
            flash('Admin logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials!', 'danger')

    return render_template('admin_login.html')  # Ensure your admin login template exists


# Route for Admin Dashboard
# Route for Admin Dashboard
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        flash('Please log in as admin to access the dashboard.', 'warning')
        return redirect(url_for('admin_login'))
    
    users = User.query.all()
    storage_info = []
    encrypted_files = []

    for user in users:
        user_files = File.query.filter_by(user_id=user.id).all()
        user_storage = sum(f.filesize for f in user_files)
        storage_info.append({
            'username': user.username,
            'files': len(user_files),
            'total_size': user_storage
        })

        for file in user_files:
            encrypted_files.append({
                'filename': file.filename,
                'filepath': file.filepath,
                'owner': user.username,
                'filesize': file.filesize,
                'download_encrypted_url': url_for('admin_download', file_id=file.id),  # Encrypted download
                'download_original_url': url_for('user_login_redirect', username=user.username, file_id=file.id)  # Original download link
            })

    return render_template('admin_dashboard.html', storage_info=storage_info, encrypted_files=encrypted_files)

# Route to redirect for original file download
@app.route('/user_login_redirect/<username>/<int:file_id>')
def user_login_redirect(username, file_id):
    flash('Please log in as the user to download the original file.', 'warning')
    return redirect(url_for('login'))

# New route for Admin downloading encrypted files
@app.route('/admin/download/<int:file_id>')
def admin_download(file_id):
    if 'admin' not in session:
        flash('Please log in as admin to access this feature.', 'warning')
        return redirect(url_for('admin_login'))

    file = File.query.get(file_id)
    if file:
        return send_file(file.filepath, as_attachment=True, download_name=file.filename + '.enc')
    flash('File not found.', 'danger')
    return redirect('/admin_dashboard')

# AES and DES encryption functions (use hashed password as key)
def encrypt_file_des(key, data):
    key_bytes = binascii.unhexlify(key)  # Convert hex to bytes
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    return encrypted_data

def encrypt_file_aes(key, data):
    key_bytes = binascii.unhexlify(key)  # Convert hex to bytes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    return encrypted_data

# Corresponding decryption functions (for completeness)
def decrypt_file_des(key, data):
    key_bytes = binascii.unhexlify(key)
    iv = data[:8]
    encrypted_data = data[8:]
    cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def decrypt_file_aes(key, data):
    key_bytes = binascii.unhexlify(key)
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Logout route for both user and admin
@app.route('/logout')
def logout():
    print(f"Session before logout: {session}")
    session.clear()
    print(f"Session after logout: {session}")
    flash('You have been logged out.', 'info')
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates the database tables inside the application context
    app.run(debug=True, port=8080)
