from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask import send_file
import hashlib
import datetime
import geocoder
import sqlite3
import socket
import os

# Authentication imports
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'my_secret_key_here'  

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  

# Database setup
def init_db():
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()

    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL
                     )''')

    # Blockchain table
    cursor.execute('''CREATE TABLE IF NOT EXISTS blockchain (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        document_hash TEXT,
                        timestamp TEXT,
                        system_id TEXT,
                        location TEXT,
                        previous_hash TEXT,
                        filepath TEXT,
                        action TEXT,
                        user_id INTEGER,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                     )''')

    # Tasks table
    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT NOT NULL,
                        description TEXT,
                        status TEXT NOT NULL,
                        assigned_to INTEGER,
                        created_by INTEGER,
                        timestamp TEXT,
                        FOREIGN KEY(assigned_to) REFERENCES users(id),
                        FOREIGN KEY(created_by) REFERENCES users(id)
                     )''')

    connection.commit()
    connection.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id_, username, role):
        self.id = id_
        self.username = username
        self.role = role

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))
    result = cursor.fetchone()
    connection.close()
    if result:
        return User(result[0], result[1], result[3])
    else:
        return None

# Function to get system address
def get_system_address():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

# Function to extract metadata and hash data
def get_metadata(data_content, previous_hash):
    timestamp = datetime.datetime.now().isoformat()
    system_id = get_system_address()

    # Get current IP-based location using geocoder
    g = geocoder.ip('me')
    location_coords = g.latlng if g.latlng else ("Location not found", "Location not found")

    # Generate hash including previous hash
    hash_input = data_content + previous_hash.encode()
    hash_object = hashlib.sha256(hash_input)
    data_hash = hash_object.hexdigest()

    return {
        "timestamp": timestamp,
        "system_id": system_id,
        "location": location_coords,
        "hash": data_hash
    }

# Route for user registration (for testing purposes)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # e.g. 'developer', 'manager', etc.

        connection = sqlite3.connect('blockchain.db')
        cursor = connection.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                           (username, password, role))
            connection.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different username.')
            return redirect(url_for('register'))
        finally:
            connection.close()
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = sqlite3.connect('blockchain.db')
        cursor = connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        result = cursor.fetchone()
        connection.close()

        if result:
            user = User(result[0], result[1], result[3])
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))
    return render_template('login.html')

# Route for user logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Route to render the HTML form
@app.route('/')
def index():
    return redirect(url_for('login'))

# Route to handle file upload
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('No file uploaded.')
            return redirect(request.url)

        file = request.files['document']
        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)

        # Save file to disk
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Read the file content for hashing
        with open(filepath, 'rb') as f:
            document_content = f.read()

        # Get previous hash
        connection = sqlite3.connect('blockchain.db')
        cursor = connection.cursor()
        cursor.execute('SELECT document_hash FROM blockchain ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        previous_hash = result[0] if result else '0'

        # Get metadata
        metadata = get_metadata(document_content, previous_hash)

        # Save to database (recording the action)
        cursor.execute('''INSERT INTO blockchain (document_hash, timestamp, system_id, location, previous_hash, filepath, action, user_id)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                       (metadata['hash'], metadata['timestamp'], metadata['system_id'],
                        str(metadata['location']), previous_hash, filepath, 'upload', current_user.id))
        connection.commit()
        connection.close()

        flash('File uploaded and processed successfully.')
        return redirect(url_for('dashboard'))

    return render_template('upload.html')

# Route to view stored documents
@app.route('/documents')
@login_required
def view_documents():
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()
    cursor.execute('''SELECT b.id, b.document_hash, b.timestamp, b.system_id, b.location,
                             b.previous_hash, b.filepath, u.username, b.action
                      FROM blockchain b
                      LEFT JOIN users u ON b.user_id = u.id
                      WHERE b.action='upload' ''')
    rows = cursor.fetchall()
    connection.close()

    documents = [
        {
            "id": row[0],
            "document_hash": row[1],
            "timestamp": row[2],
            "system_id": row[3],
            "location": row[4],
            "previous_hash": row[5],
            "filepath": row[6],
            "username": row[7],
            "action": row[8]
        }
        for row in rows
    ]

    return render_template('documents.html', documents=documents)

# Route to view the blockchain
@app.route('/blockchain')
@login_required
def view_blockchain():
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()
    cursor.execute('''SELECT b.id, b.document_hash, b.previous_hash, b.timestamp, b.action, u.username
                      FROM blockchain b
                      LEFT JOIN users u ON b.user_id = u.id
                      ORDER BY b.id''')
    rows = cursor.fetchall()
    connection.close()

    chain = [
        {
            "id": row[0],
            "document_hash": row[1],
            "previous_hash": row[2],
            "timestamp": row[3],
            "action": row[4],
            "username": row[5]
        }
        for row in rows
    ]

    return render_template('blockchain.html', chain=chain)

# Route to view/download a document
@app.route('/download/<int:document_id>')
@login_required
def download_document(document_id):
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()
    cursor.execute('SELECT filepath FROM blockchain WHERE id=?', (document_id,))
    result = cursor.fetchone()
    connection.close()

    if result:
        filepath = result[0]
        try:
            return send_file(filepath, as_attachment=True)
        except FileNotFoundError:
            flash('File not found on server.')
            return redirect(url_for('documents'))
    else:
        flash('Document not found.')
        return redirect(url_for('documents'))

# Routes for task management
@app.route('/tasks')
@login_required
def view_tasks():
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()
    cursor.execute('''SELECT t.id, t.title, t.description, t.status, t.timestamp,
                             u1.username as assigned_to_username, u2.username as created_by_username
                      FROM tasks t
                      LEFT JOIN users u1 ON t.assigned_to = u1.id
                      LEFT JOIN users u2 ON t.created_by = u2.id''')
    rows = cursor.fetchall()
    connection.close()

    tasks = [
        {
            "id": row[0],
            "title": row[1],
            "description": row[2],
            "status": row[3],
            "timestamp": row[4],
            "assigned_to": row[5],
            "created_by": row[6]
        }
        for row in rows
    ]

    return render_template('tasks.html', tasks=tasks)

@app.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task():
    # Only users with the "manager" role can create tasks
    if current_user.role != 'manager':
        flash('You do not have permission to create tasks.')
        return redirect(url_for('view_tasks'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        assigned_to = request.form['assigned_to']
        status = 'Open'
        timestamp = datetime.datetime.now().isoformat()

        connection = sqlite3.connect('blockchain.db')
        cursor = connection.cursor()
        cursor.execute('INSERT INTO tasks (title, description, status, assigned_to, created_by, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
                       (title, description, status, assigned_to, current_user.id, timestamp))
        connection.commit()

        # Add to blockchain
        task_content = f'{title}{description}{status}{assigned_to}{current_user.id}{timestamp}'.encode()
        cursor.execute('SELECT document_hash FROM blockchain ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        previous_hash = result[0] if result else '0'
        metadata = get_metadata(task_content, previous_hash)

        cursor.execute('''INSERT INTO blockchain (document_hash, timestamp, system_id, location, previous_hash, action, user_id)
                          VALUES (?, ?, ?, ?, ?, ?, ?)''',
                       (metadata['hash'], metadata['timestamp'], metadata['system_id'],
                        str(metadata['location']), previous_hash, 'create_task', current_user.id))
        connection.commit()
        connection.close()

        flash('Task created successfully.')
        return redirect(url_for('view_tasks'))

    # Get list of users to assign task
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    connection.close()

    return render_template('create_task.html', users=users)

@app.route('/tasks/update/<int:task_id>', methods=['GET', 'POST'])
@login_required
def update_task(task_id):
    connection = sqlite3.connect('blockchain.db')
    cursor = connection.cursor()

    if request.method == 'POST':
        status = request.form['status']

        cursor.execute('UPDATE tasks SET status=? WHERE id=?', (status, task_id))
        connection.commit()

        # Add to blockchain (documenting the update action)
        task_content = f'Update Task {task_id} Status to {status}'.encode()
        cursor.execute('SELECT document_hash FROM blockchain ORDER BY id DESC LIMIT 1')
        result = cursor.fetchone()
        previous_hash = result[0] if result else '0'
        metadata = get_metadata(task_content, previous_hash)

        cursor.execute('''INSERT INTO blockchain (document_hash, timestamp, system_id, location, previous_hash, action, user_id)
                          VALUES (?, ?, ?, ?, ?, ?, ?)''',
                       (metadata['hash'], metadata['timestamp'], metadata['system_id'],
                        str(metadata['location']), previous_hash, 'update_task', current_user.id))
        connection.commit()
        connection.close()

        flash('Task updated successfully.')
        return redirect(url_for('view_tasks'))

    # Retrieve task details
    cursor.execute('SELECT id, title, description, status FROM tasks WHERE id=?', (task_id,))
    task = cursor.fetchone()
    connection.close()

    if task:
        task_details = {
            "id": task[0],
            "title": task[1],
            "description": task[2],
            "status": task[3]
        }
        return render_template('update_task.html', task=task_details)
    else:
        flash('Task not found.')
        return redirect(url_for('view_tasks'))

# Initialize the database
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
