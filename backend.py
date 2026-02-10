#!/usr/bin/env python3
"""
ChatApp Backend - Simple Flask Server for Real-time Chat Application
Uses SQLite for persistence and supports CORS for frontend communication
"""

import os
import json
import secrets
import sqlite3
import bcrypt
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from contextlib import contextmanager

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app)

# Database setup
DATABASE = 'chatapp.db'

def get_db():
    """Get database connection"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close database connection"""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database tables"""
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            avatar_url TEXT,
            bio TEXT,
            status TEXT DEFAULT 'offline',
            email_verified BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Conversations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT DEFAULT 'direct',
            created_by TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Conversation members table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversation_members (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(conversation_id, user_id)
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            content TEXT,
            type TEXT DEFAULT 'text',
            file_url TEXT,
            file_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id),
            FOREIGN KEY (sender_id) REFERENCES users(id)
        )
    ''')
    
    # Notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            read BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Call history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS calls (
            id TEXT PRIMARY KEY,
            initiator_id TEXT NOT NULL,
            receiver_id TEXT,
            conversation_id TEXT,
            call_type TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TIMESTAMP,
            ended_at TIMESTAMP,
            duration INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (initiator_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id),
            FOREIGN KEY (conversation_id) REFERENCES conversations(id)
        )
    ''')
    
    db.commit()
    db.close()

def dict_from_row(row):
    """Convert sqlite3.Row to dict"""
    return dict(row) if row else None

# JWT Helper Functions
def generate_jwt_token(user_id, expires_in=7):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=expires_in),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return jsonify({'message': 'Invalid or expired token'}), 401
        
        request.user_id = user_id
        return f(*args, **kwargs)
    
    return decorated

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/auth/signup', methods=['POST'])
def signup():
    """Register new user"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password') or not data.get('full_name'):
            return jsonify({'message': 'Missing required fields'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (data['email'],))
        if cursor.fetchone():
            return jsonify({'message': 'User already exists'}), 409
        
        # Hash password
        password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user
        user_id = secrets.token_urlsafe(16)
        cursor.execute('''
            INSERT INTO users (id, email, full_name, password_hash, email_verified)
            VALUES (?, ?, ?, ?, 1)
        ''', (user_id, data['email'], data['full_name'], password_hash))
        db.commit()
        
        # Generate token
        token = generate_jwt_token(user_id)
        
        return jsonify({
            'token': token,
            'user': {
                'id': user_id,
                'email': data['email'],
                'name': data['full_name']
            }
        }), 201
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Missing credentials'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        # Get user
        cursor.execute('SELECT id, full_name, password_hash FROM users WHERE email = ?', (data['email'],))
        user = cursor.fetchone()
        
        if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Generate token
        token = generate_jwt_token(user['id'])
        
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'email': data['email'],
                'name': user['full_name']
            }
        }), 200
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== CONVERSATIONS ENDPOINTS ====================

@app.route('/conversations', methods=['GET'])
@token_required
def get_conversations():
    """Get user conversations"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            SELECT DISTINCT c.id, c.name, c.type, c.created_at
            FROM conversations c
            JOIN conversation_members cm ON c.id = cm.conversation_id
            WHERE cm.user_id = ?
            ORDER BY c.updated_at DESC
        ''', (request.user_id,))
        
        conversations = cursor.fetchall()
        result = []
        
        for conv in conversations:
            # Get members count
            cursor.execute('SELECT COUNT(*) as count FROM conversation_members WHERE conversation_id = ?', (conv['id'],))
            members_count = cursor.fetchone()['count']
            
            # Get last message
            cursor.execute('''
                SELECT content, created_at FROM messages 
                WHERE conversation_id = ? 
                ORDER BY created_at DESC LIMIT 1
            ''', (conv['id'],))
            last_msg = cursor.fetchone()
            
            result.append({
                'id': conv['id'],
                'name': conv['name'],
                'type': conv['type'],
                'members': members_count,
                'last_message': last_msg['content'] if last_msg else None,
                'last_message_time': last_msg['created_at'] if last_msg else None,
                'created_at': conv['created_at']
            })
        
        return jsonify({'conversations': result}), 200
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/conversations/<conv_id>/messages', methods=['GET'])
@token_required
def get_messages(conv_id):
    """Get conversation messages"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Check if user is member
        cursor.execute('''
            SELECT 1 FROM conversation_members 
            WHERE conversation_id = ? AND user_id = ?
        ''', (conv_id, request.user_id))
        
        if not cursor.fetchone():
            return jsonify({'message': 'Access denied'}), 403
        
        # Get messages
        cursor.execute('''
            SELECT id, sender_id, content, type, file_url, file_name, created_at 
            FROM messages 
            WHERE conversation_id = ? 
            ORDER BY created_at ASC
        ''', (conv_id,))
        
        messages = cursor.fetchall()
        result = [dict(msg) for msg in messages]
        
        return jsonify({'messages': result}), 200
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/conversations/<conv_id>/messages', methods=['POST'])
@token_required
def send_message(conv_id):
    """Send message to conversation"""
    try:
        data = request.get_json()
        
        db = get_db()
        cursor = db.cursor()
        
        # Check if user is member
        cursor.execute('''
            SELECT 1 FROM conversation_members 
            WHERE conversation_id = ? AND user_id = ?
        ''', (conv_id, request.user_id))
        
        if not cursor.fetchone():
            return jsonify({'message': 'Access denied'}), 403
        
        # Create message
        msg_id = secrets.token_urlsafe(16)
        msg_type = data.get('type', 'text')
        
        cursor.execute('''
            INSERT INTO messages (id, conversation_id, sender_id, content, type)
            VALUES (?, ?, ?, ?, ?)
        ''', (msg_id, conv_id, request.user_id, data.get('content'), msg_type))
        
        # Update conversation timestamp
        cursor.execute('''
            UPDATE conversations 
            SET updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
        ''', (conv_id,))
        
        db.commit()
        
        return jsonify({
            'id': msg_id,
            'sender_id': request.user_id,
            'content': data.get('content'),
            'type': msg_type,
            'created_at': datetime.utcnow().isoformat()
        }), 201
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/conversations', methods=['POST'])
@token_required
def create_conversation():
    """Create new conversation"""
    try:
        data = request.get_json()
        
        db = get_db()
        cursor = db.cursor()
        
        # Create conversation
        conv_id = secrets.token_urlsafe(16)
        conv_type = data.get('type', 'group')
        
        cursor.execute('''
            INSERT INTO conversations (id, name, type, created_by)
            VALUES (?, ?, ?, ?)
        ''', (conv_id, data.get('name'), conv_type, request.user_id))
        
        # Add members
        members = data.get('members', [request.user_id])
        if request.user_id not in members:
            members.append(request.user_id)
        
        for member_id in members:
            member_conv_id = secrets.token_urlsafe(16)
            cursor.execute('''
                INSERT INTO conversation_members (id, conversation_id, user_id)
                VALUES (?, ?, ?)
            ''', (member_conv_id, conv_id, member_id))
        
        db.commit()
        
        return jsonify({
            'id': conv_id,
            'name': data.get('name'),
            'type': conv_type,
            'members': members
        }), 201
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== NOTIFICATIONS ENDPOINTS ====================

@app.route('/notifications', methods=['GET'])
@token_required
def get_notifications():
    """Get user notifications"""
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''
            SELECT id, title, message, type, read, created_at 
            FROM notifications 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        ''', (request.user_id,))
        
        notifications = cursor.fetchall()
        result = [dict(notif) for notif in notifications]
        
        return jsonify({'notifications': result}), 200
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

# ==================== HEALTH CHECK ====================

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()}), 200

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error'}), 500

# ==================== MAIN ====================

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run Flask app
    print('Starting ChatApp Backend on http://localhost:5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
