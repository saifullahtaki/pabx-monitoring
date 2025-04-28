from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from asterisk.manager import Manager
import sqlite3
import re
import logging
import time
from functools import wraps
from uuid import uuid4
import subprocess
import platform
import threading

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Asterisk AMI setup
manager = Manager()

def connect_ami():
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Attempting to connect to AMI at 192.168.25.2:5038 (attempt {attempt + 1}/{max_retries})")
            manager.connect('192.168.25.2', port=5038)
            manager.login('testuser', 'TestPass123#')
            logger.info("AMI connection successful")
            return True
        except Exception as e:
            logger.error(f"AMI connection failed (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2)
    logger.error("Failed to connect to AMI after multiple attempts")
    return False

# Connect to AMI at startup (log error but don't crash app)
if not connect_ami():
    logger.error("Failed to connect to AMI. Asterisk features disabled. Check credentials, IP, or manager.conf permissions.")

# Function to fetch channel stats (pjsip show channelstats)
def get_channel_stats():
    try:
        logger.info("Fetching channel stats with command: pjsip show channelstats")
        response = manager.command('pjsip show channelstats')
        logger.debug(f"Full AMI response: {response.__dict__}")
        
        raw_lines = [line for line in response.response if line.startswith('Output:')]
        raw_data = '\n'.join([line.replace('Output: ', '') for line in raw_lines])
        logger.debug(f"Raw channel stats response:\n{raw_data}")
        
        if not raw_data.strip():
            logger.warning("No data returned from pjsip show channelstats")
            return []

        lines = raw_data.split('\n')
        stats = []
        for line in lines:
            line = line.strip()
            if (not line or 
                line.startswith('Channel:') or 
                'Receive' in line or 
                '==' in line or 
                'Objects found' in line):
                continue
            match = re.match(
                r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+)\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)',
                line
            )
            if match:
                try:
                    channel_stats = {
                        'bridge_id': match.group(1),
                        'channel_id': match.group(2),
                        'uptime': match.group(3),
                        'codec': match.group(4),
                        'rx_count': int(match.group(5)),
                        'rx_lost': int(match.group(6)),
                        'rx_loss_pct': float(match.group(7)),
                        'rx_jitter': float(match.group(8)),
                        'tx_count': int(match.group(9)),
                        'tx_lost': int(match.group(10)),
                        'tx_loss_pct': float(match.group(11)),
                        'tx_jitter': float(match.group(12)),
                        'rtt': float(match.group(13))
                    }
                    stats.append(channel_stats)
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse channel stats line: {line} - Error: {e}")
                    continue
            else:
                logger.debug(f"Line did not match expected format: {line}")
        logger.debug(f"Parsed channel stats: {stats}")
        return stats
    except Exception as e:
        logger.error(f"Error fetching channel stats: {e}")
        return []

# Function to fetch core show channels
def get_core_channels():
    try:
        logger.info("Fetching core channels with command: core show channels")
        response = manager.command('core show channels')
        logger.debug(f"Full AMI core show channels response: {response.__dict__}")
        
        raw_lines = [line for line in response.response if line.startswith('Output:')]
        raw_data = '\n'.join([line.replace('Output: ', '') for line in raw_lines])
        logger.debug(f"Raw core show channels response:\n{raw_data}")
        
        if not raw_data.strip():
            logger.warning("No data returned from core show channels")
            return []

        lines = raw_data.split('\n')
        channels = []
        for line in lines:
            line = line.strip()
            if (not line or 
                line.startswith('Channel') or 
                'active call' in line or 
                'active channel' in line):
                continue
            match = re.match(
                r'(\S+)\s+(\S+)\s+(\S+)\s+(\d+:\d+:\d+)',
                line
            )
            if match:
                try:
                    channels.append({
                        'channel': match.group(1),
                        'location': match.group(2),
                        'application': match.group(3),
                        'duration': match.group(4)
                    })
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse core show channels line: {line} - Error: {e}")
                    continue
            else:
                logger.debug(f"Line did not match expected format: {line}")
        logger.debug(f"Parsed core channels: {channels}")
        return channels
    except Exception as e:
        logger.error(f"Error fetching core show channels: {e}")
        return []

# Function to fetch pjsip show endpoints
def get_pjsip_endpoints():
    try:
        logger.info("Fetching PJSIP endpoints with command: pjsip show endpoints")
        response = manager.command('pjsip show endpoints')
        logger.debug(f"Full AMI pjsip show endpoints response: {response.__dict__}")
        
        raw_lines = [line for line in response.response if line.startswith('Output:')]
        raw_data = '\n'.join([line.replace('Output: ', '') for line in raw_lines])
        logger.debug(f"Raw pjsip show endpoints response:\n{raw_data}")
        
        if not raw_data.strip():
            logger.warning("No data returned from pjsip show endpoints")
            return []

        lines = raw_data.split('\n')
        endpoints = []
        for line in lines:
            line = line.strip()
            if (not line or 
                line.startswith('Endpoint:') or 
                'Objects found' in line):
                continue
            match = re.match(
                r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)',  # Adjust based on actual output
                line
            )
            if match:
                try:
                    endpoints.append({
                        'endpoint': match.group(1),
                        'state': match.group(2),
                        'aor': match.group(3),
                        'auth': match.group(4),
                        'transport': match.group(5)
                    })
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse pjsip show endpoints line: {line} - Error: {e}")
                    continue
            else:
                logger.debug(f"Line did not match expected format: {line}")
        logger.debug(f"Parsed PJSIP endpoints: {endpoints}")
        return endpoints
    except Exception as e:
        logger.error(f"Error fetching pjsip show endpoints: {e}")
        return []

# Function to fetch pjsip show contacts
def get_pjsip_contacts():
    try:
        logger.info("Fetching PJSIP contacts with command: pjsip show contacts")
        response = manager.command('pjsip show contacts')
        logger.debug(f"Full AMI pjsip show contacts response: {response.__dict__}")
        
        raw_lines = [line for line in response.response if line.startswith('Output:')]
        raw_data = '\n'.join([line.replace('Output: ', '') for line in raw_lines])
        logger.debug(f"Raw pjsip show contacts response:\n{raw_data}")
        
        if not raw_data.strip():
            logger.warning("No data returned from pjsip show contacts")
            return []

        lines = raw_data.split('\n')
        contacts = []
        for line in lines:
            line = line.strip()
            if (not line or 
                line.startswith('Contact:') or 
                'Objects found' in line):
                continue
            match = re.match(
                r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)',  # Adjust based on actual output
                line
            )
            if match:
                try:
                    contacts.append({
                        'contact': match.group(1),
                        'hash': match.group(2),
                        'status': match.group(3),
                        'rtt': match.group(4)
                    })
                except (ValueError, IndexError) as e:
                    logger.warning(f"Failed to parse pjsip show contacts line: {line} - Error: {e}")
                    continue
            else:
                logger.debug(f"Line did not match expected format: {line}")
        logger.debug(f"Parsed PJSIP contacts: {contacts}")
        return contacts
    except Exception as e:
        logger.error(f"Error fetching pjsip show contacts: {e}")
        return []

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        status TEXT
    )''')
    # Phone Status table
    c.execute('''CREATE TABLE IF NOT EXISTS phone_status (
        id TEXT PRIMARY KEY,
        extension TEXT,
        number TEXT,
        name TEXT,
        location TEXT,
        ip TEXT,
        status TEXT
    )''')
    # Locations table
    c.execute('''CREATE TABLE IF NOT EXISTS locations (
        id TEXT PRIMARY KEY,
        name TEXT UNIQUE
    )''')
    # Create default admin if not exists
    default_admin = ('admin', generate_password_hash('DevOps@2030#'), 'admin', 'approved')
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        c.execute('INSERT INTO users (id, username, password, role, status) VALUES (?, ?, ?, ?, ?)',
                 (str(uuid4()), default_admin[0], default_admin[1], default_admin[2], default_admin[3]))
    # Insert default locations if not exists
    default_locations = ['Office', 'Remote', 'Branch A', 'Branch B']
    for loc in default_locations:
        c.execute('SELECT * FROM locations WHERE name = ?', (loc,))
        if not c.fetchone():
            c.execute('INSERT INTO locations (id, name) VALUES (?, ?)', (str(uuid4()), loc))
    conn.commit()
    conn.close()

init_db()

# Function to ping an IP and determine status
def ping_ip(ip):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if result.returncode == 0:
            logger.debug(f"Ping successful for IP {ip}")
            return 'Active'
        else:
            logger.debug(f"Ping failed for IP {ip}")
            return 'In-Active'
    except subprocess.TimeoutExpired:
        logger.debug(f"Ping timeout for IP {ip}")
        return 'In-Active'
    except Exception as e:
        logger.error(f"Error pinging IP {ip}: {e}")
        return 'In-Active'

# Function to update phone status entries with ping results
def update_phone_status():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, ip FROM phone_status')
    entries = c.fetchall()
    for entry in entries:
        entry_id, ip = entry
        if ip:
            status = ping_ip(ip)
            logger.debug(f"Updating status for IP {ip} to {status}")
            c.execute('UPDATE phone_status SET status = ? WHERE id = ?', (status, entry_id))
    conn.commit()
    conn.close()

# Background thread for continuous pinging
def background_ping():
    while True:
        try:
            logger.info("Running background ping for phone status")
            update_phone_status()
        except Exception as e:
            logger.error(f"Error in background ping: {e}")
        time.sleep(5)  # Ping every 5 seconds

# Start background ping thread
ping_thread = threading.Thread(target=background_ping, daemon=True)
ping_thread.start()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if user and user[0] != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/api/call_data')
@login_required
def api_call_data():
    try:
        stats = get_channel_stats()
        channels = get_core_channels()
        endpoints = get_pjsip_endpoints()
        contacts = get_pjsip_contacts()
        
        calls = []
        phones = []
        for stat in stats:
            uptime_parts = stat['uptime'].split(':')
            duration = int(uptime_parts[0]) * 3600 + int(uptime_parts[1]) * 60 + int(uptime_parts[2])
            calls.append({
                'channel_id': stat['channel_id'],
                'caller': stat['channel_id'].split('-')[0],
                'callee': 'Unknown',
                'status': 'Active',
                'duration': duration,
                'packet_loss': stat['tx_loss_pct'],
                'jitter': stat['tx_jitter'],
                'rtt': stat['rtt'],
                'codec': stat['codec']
            })
            extension = stat['channel_id'].split('-')[0]
            phones.append({
                'extension': extension,
                'status': 'Available',
                'packet_loss': stat['tx_loss_pct']
            })
        # Fetch phone status entries
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, extension, number, name, location, ip, status FROM phone_status')
        phone_status_entries = [
            {
                'id': row[0],
                'extension': row[1],
                'number': row[2],
                'name': row[3],
                'location': row[4],
                'ip': row[5],
                'status': row[6]
            }
            for row in c.fetchall()
        ]
        conn.close()
        logger.info(f"Returning channel stats: {len(stats)} stats, core channels: {len(channels)} channels, endpoints: {len(endpoints)}, contacts: {len(contacts)}, phone_status: {len(phone_status_entries)}")
        return jsonify({
            'calls': calls,
            'phones': phones,
            'channels': channels,
            'endpoints': endpoints,
            'contacts': contacts,
            'phone_status': phone_status_entries
        })
    except Exception as e:
        logger.error(f"Error in api_call_data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/locations', methods=['GET'])
@login_required
def get_locations():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, name FROM locations')
    locations = [{'id': row[0], 'name': row[1]} for row in c.fetchall()]
    conn.close()
    return jsonify({'locations': locations})

@app.route('/add_location', methods=['POST'])
@login_required
def add_location():
    location_name = request.form['location_name']
    if not location_name:
        flash('Location name cannot be empty.', 'error')
        return redirect(request.referrer)
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO locations (id, name) VALUES (?, ?)', (str(uuid4()), location_name))
        conn.commit()
        flash('Location added successfully.', 'success')
    except sqlite3.IntegrityError:
        flash('Location already exists.', 'error')
    finally:
        conn.close()
    return redirect(request.referrer)

@app.route('/edit_location/<location_id>', methods=['POST'])
@login_required
def edit_location(location_id):
    new_name = request.form['location_name']
    if not new_name:
        flash('Location name cannot be empty.', 'error')
        return redirect(request.referrer)
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('UPDATE locations SET name = ? WHERE id = ?', (new_name, location_id))
        conn.commit()
        flash('Location updated successfully.', 'success')
    except sqlite3.IntegrityError:
        flash('Location name already exists.', 'error')
    finally:
        conn.close()
    return redirect(request.referrer)

@app.route('/delete_location/<location_id>')
@login_required
def delete_location(location_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Check if location is used in phone_status
    c.execute('SELECT COUNT(*) FROM phone_status WHERE location = (SELECT name FROM locations WHERE id = ?)', (location_id,))
    if c.fetchone()[0] > 0:
        flash('Cannot delete location in use by phone status entries.', 'error')
    else:
        c.execute('DELETE FROM locations WHERE id = ?', (location_id,))
        conn.commit()
        flash('Location deleted successfully.', 'success')
    conn.close()
    return redirect(request.referrer)

@app.route('/add_phone_status', methods=['POST'])
@login_required
def add_phone_status():
    extension = request.form['extension']
    number = request.form['number']
    name = request.form['name']
    location = request.form['location']
    ip = request.form['ip']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    entry_id = str(uuid4())
    c.execute('INSERT INTO phone_status (id, extension, number, name, location, ip, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
              (entry_id, extension, number, name, location, ip, 'Unknown'))
    conn.commit()
    conn.close()
    # Update status with ping result
    update_phone_status()
    flash('Phone status entry added successfully.', 'success')
    return redirect(request.referrer)

@app.route('/modify_phone_status/<entry_id>', methods=['POST'])
@login_required
def modify_phone_status(entry_id):
    extension = request.form['extension']
    number = request.form['number']
    name = request.form['name']
    location = request.form['location']
    ip = request.form['ip']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE phone_status SET extension = ?, number = ?, name = ?, location = ?, ip = ?, status = ? WHERE id = ?',
              (extension, number, name, location, ip, 'Unknown', entry_id))
    conn.commit()
    conn.close()
    # Update status with ping result
    update_phone_status()
    flash('Phone status entry modified successfully.', 'success')
    return redirect(request.referrer)

@app.route('/remove_phone_status/<entry_id>')
@login_required
def remove_phone_status(entry_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM phone_status WHERE id = ?', (entry_id,))
    conn.commit()
    conn.close()
    flash('Phone status entry removed successfully.', 'success')
    return redirect(request.referrer)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, username, password, role, status FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password) and user[4] == 'approved':
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            flash('Login successful!', 'success')
            if user[3] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials or account not approved.', 'error')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('SELECT username FROM users WHERE username = ?', (username,))
            if c.fetchone():
                flash('Username already exists.', 'error')
            else:
                user_id = str(uuid4())
                hashed_password = generate_password_hash(password)
                c.execute('INSERT INTO users (id, username, password, role, status) VALUES (?, ?, ?, ?, ?)',
                         (user_id, username, hashed_password, role, 'pending'))
                conn.commit()
                flash('Registration request sent. Waiting for admin approval.', 'success')
                return redirect(url_for('login'))
        finally:
            conn.close()
    return render_template('auth/register.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('Logged out successfully.', 'success')
    return render_template('auth/logout.html')

# Admin Routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/admin_dashboard.html')

@app.route('/admin/add_locations', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_locations():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, name FROM locations')
    locations = c.fetchall()
    conn.close()
    return render_template('admin/add_locations.html', locations=locations)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Handle new user creation
    if request.method == 'POST' and 'new_username' in request.form:
        username = request.form['new_username']
        password = request.form['new_password']
        role = request.form['new_role']
        
        c.execute('SELECT username FROM users WHERE username = ?', (username,))
        if c.fetchone():
            flash('Username already exists.', 'error')
        else:
            user_id = str(uuid4())
            hashed_password = generate_password_hash(password)
            c.execute('INSERT INTO users (id, username, password, role, status) VALUES (?, ?, ?, ?, ?)',
                     (user_id, username, hashed_password, role, 'approved'))
            conn.commit()
            flash('New user created successfully.', 'success')
    
    c.execute('SELECT id, username, role, status FROM users WHERE username != ?', ('admin',))
    users = c.fetchall()
    c.execute('SELECT id, username, role, status FROM users WHERE username = ?', ('admin',))
    admin_user = c.fetchone()
    if admin_user:
        users = [admin_user] + list(users)
    conn.close()
    return render_template('admin/admin_users.html', users=users)

@app.route('/admin/update_role/<user_id>', methods=['POST'])
@login_required
@admin_required
def update_role(user_id):
    new_role = request.form['role']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user[0] == 'admin':
        return jsonify({'success': False, 'message': 'Cannot change admin role.'})
    c.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Role updated successfully.'})

@app.route('/admin/user_requests')
@login_required
@admin_required
def admin_user_requests():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, role FROM users WHERE status = ?', ('pending',))
    requests = c.fetchall()
    conn.close()
    return render_template('admin/admin_user_requests.html', requests=requests)

@app.route('/admin/approve_user/<user_id>')
@login_required
@admin_required
def approve_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET status = ? WHERE id = ?', ('approved', user_id))
    conn.commit()
    conn.close()
    flash('User approved successfully.', 'success')
    return redirect(url_for('admin_user_requests'))

@app.route('/admin/reject_user/<user_id>')
@login_required
@admin_required
def reject_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User request rejected.', 'success')
    return redirect(url_for('admin_user_requests'))

@app.route('/admin/delete_user/<user_id>')
@login_required
@admin_required
def delete_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    if user and user[0] == 'admin':
        flash('Cannot delete admin user.', 'error')
    else:
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash('User deleted successfully.', 'success')
    conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/reset_user_password/<user_id>', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    new_password = request.form['new_password']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    hashed_password = generate_password_hash(new_password)
    c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user_id))
    conn.commit()
    conn.close()
    flash('User password reset successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/change_password', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if check_password_hash(user[0], old_password):
            hashed_password = generate_password_hash(new_password)
            c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, session['user_id']))
            conn.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Incorrect old password.', 'error')
        conn.close()
    return render_template('admin/admin_change_password.html')

# User Routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user/user_dashboard.html')

@app.route('/user/add_locations', methods=['GET', 'POST'])
@login_required
def user_add_locations():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, name FROM locations')
    locations = c.fetchall()
    conn.close()
    return render_template('user/add_locations.html', locations=locations)

@app.route('/user/change_password', methods=['GET', 'POST'])
@login_required
def user_change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if check_password_hash(user[0], old_password):
            hashed_password = generate_password_hash(new_password)
            c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, session['user_id']))
            conn.commit()
            flash('Password changed successfully.', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Incorrect old password.', 'error')
        conn.close()
    return render_template('user/user_change_password.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5005)
