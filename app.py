import os
import json
import secrets
import uuid
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

import bcrypt
import jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
import requests
from geopy.distance import geodesic

load_dotenv()

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Initialize Supabase Client
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_KEY = os.getenv('SUPABASE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Email configuration (using placeholder - implement with your email service)
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')

# JWT Helper Functions
def generate_jwt_token(user_id, expires_in=7):
    """Generate JWT token for user"""
    payload = {
        'user_id': str(user_id),
        'exp': datetime.utcnow() + timedelta(days=expires_in),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
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

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Register new user"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password') or not data.get('full_name'):
            return jsonify({'message': 'Missing required fields'}), 400
        
        # Check if user already exists
        existing_user = supabase.table('users').select('id').eq('email', data['email']).execute()
        if existing_user.data:
            return jsonify({'message': 'User already exists'}), 409
        
        # Hash password
        password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        
        # Create user
        user_data = {
            'email': data['email'],
            'password_hash': password_hash,
            'full_name': data['full_name'],
            'verification_token': verification_token,
            'verification_token_expires': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        
        user = supabase.table('users').insert(user_data).execute()
        user_id = user.data[0]['id']
        
        # Create user profile
        profile_data = {
            'user_id': user_id,
            'last_seen': datetime.utcnow().isoformat()
        }
        supabase.table('user_profiles').insert(profile_data).execute()
        
        # Create initial conversation for user (for future use)
        
        # Send verification email (implement with your email service)
        send_verification_email(data['email'], verification_token, user_id)
        
        token = generate_jwt_token(user_id)
        
        return jsonify({
            'message': 'User registered successfully. Please verify your email.',
            'user_id': user_id,
            'token': token,
            'email': data['email']
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Registration failed: {str(e)}'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password required'}), 400
        
        # Get user
        user_result = supabase.table('users').select('*').eq('email', data['email']).execute()
        
        if not user_result.data:
            return jsonify({'message': 'Invalid credentials'}), 401
        
        user = user_result.data[0]
        
        if not user['is_active']:
            return jsonify({'message': 'Account is inactive'}), 403
        
        # Verify password
        if not bcrypt.checkpw(data['password'].encode('utf-8'), user['password_hash'].encode('utf-8')):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        user_agent = request.headers.get('User-Agent', '')
        ip_address = request.remote_addr
        
        session_data = {
            'user_id': user['id'],
            'session_token': session_token,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'expires_at': (datetime.utcnow() + timedelta(days=7)).isoformat()
        }
        supabase.table('user_sessions').insert(session_data).execute()
        
        # Update user status
        supabase.table('users').update({'status': 'online'}).eq('id', user['id']).execute()
        supabase.table('user_profiles').update({'last_seen': datetime.utcnow().isoformat()}).eq('user_id', user['id']).execute()
        
        token = generate_jwt_token(user['id'])
        
        return jsonify({
            'message': 'Login successful',
            'user_id': user['id'],
            'token': token,
            'email': user['email'],
            'full_name': user['full_name'],
            'avatar_url': user['avatar_url'],
            'email_verified': user['email_verified']
        }), 200
        
    except Exception as e:
        return jsonify({'message': f'Login failed: {str(e)}'}), 500

@app.route('/api/auth/verify-email', methods=['POST'])
def verify_email():
    """Verify email address"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'message': 'Token required'}), 400
        
        # Find user with token
        user_result = supabase.table('users').select('*').eq('verification_token', token).execute()
        
        if not user_result.data:
            return jsonify({'message': 'Invalid token'}), 400
        
        user = user_result.data[0]
        
        # Check if token expired
        if datetime.fromisoformat(user['verification_token_expires']) < datetime.utcnow():
            return jsonify({'message': 'Token expired'}), 400
        
        # Update user
        supabase.table('users').update({
            'email_verified': True,
            'verification_token': None,
            'verification_token_expires': None
        }).eq('id', user['id']).execute()
        
        return jsonify({'message': 'Email verified successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Verification failed: {str(e)}'}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'message': 'Email required'}), 400
        
        # Get user
        user_result = supabase.table('users').select('id').eq('email', email).execute()
        
        if not user_result.data:
            # Don't reveal if email exists (security)
            return jsonify({'message': 'If email exists, reset link has been sent'}), 200
        
        user_id = user_result.data[0]['id']
        
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        
        # Store reset token
        token_data = {
            'user_id': user_id,
            'token': reset_token,
            'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }
        supabase.table('password_reset_tokens').insert(token_data).execute()
        
        # Send reset email
        send_password_reset_email(email, reset_token, user_id)
        
        return jsonify({'message': 'If email exists, reset link has been sent'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Request failed: {str(e)}'}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('new_password')
        
        if not token or not new_password:
            return jsonify({'message': 'Token and password required'}), 400
        
        # Find token
        token_result = supabase.table('password_reset_tokens').select('*').eq('token', token).eq('used', False).execute()
        
        if not token_result.data:
            return jsonify({'message': 'Invalid or used token'}), 400
        
        token_obj = token_result.data[0]
        
        # Check if expired
        if datetime.fromisoformat(token_obj['expires_at']) < datetime.utcnow():
            return jsonify({'message': 'Token expired'}), 400
        
        # Hash new password
        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update user
        supabase.table('users').update({'password_hash': password_hash}).eq('id', token_obj['user_id']).execute()
        
        # Mark token as used
        supabase.table('password_reset_tokens').update({'used': True}).eq('id', token_obj['id']).execute()
        
        return jsonify({'message': 'Password reset successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Reset failed: {str(e)}'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    """Logout user"""
    try:
        # Update user status
        supabase.table('users').update({'status': 'offline'}).eq('id', request.user_id).execute()
        supabase.table('user_profiles').update({'last_seen': datetime.utcnow().isoformat()}).eq('user_id', request.user_id).execute()
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Logout failed: {str(e)}'}), 500

@app.route('/api/auth/accept-terms', methods=['POST'])
@token_required
def accept_terms():
    """Accept terms and conditions"""
    try:
        ip_address = request.remote_addr
        
        terms_data = {
            'user_id': request.user_id,
            'version': '1.0',
            'ip_address': ip_address
        }
        supabase.table('terms_acceptance').insert(terms_data).execute()
        
        return jsonify({'message': 'Terms accepted'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to accept terms: {str(e)}'}), 500

# ==================== USER ENDPOINTS ====================

@app.route('/api/users/<user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    """Get user details"""
    try:
        user_result = supabase.table('users').select('id, email, full_name, avatar_url, bio, status, created_at').eq('id', user_id).execute()
        
        if not user_result.data:
            return jsonify({'message': 'User not found'}), 404
        
        user = user_result.data[0]
        profile_result = supabase.table('user_profiles').select('*').eq('user_id', user_id).execute()
        
        if profile_result.data:
            user['profile'] = profile_result.data[0]
        
        return jsonify(user), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to get user: {str(e)}'}), 500

@app.route('/api/users/me', methods=['GET'])
@token_required
def get_current_user():
    """Get current user details"""
    try:
        user_result = supabase.table('users').select('id, email, full_name, avatar_url, bio, status, theme').eq('id', request.user_id).execute()
        
        if not user_result.data:
            return jsonify({'message': 'User not found'}), 404
        
        user = user_result.data[0]
        profile_result = supabase.table('user_profiles').select('*').eq('user_id', request.user_id).execute()
        
        if profile_result.data:
            user['profile'] = profile_result.data[0]
        
        return jsonify(user), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to get user: {str(e)}'}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    """Update user profile"""
    try:
        if user_id != request.user_id:
            return jsonify({'message': 'Unauthorized'}), 403
        
        data = request.get_json()
        update_data = {}
        
        if 'full_name' in data:
            update_data['full_name'] = data['full_name']
        if 'bio' in data:
            update_data['bio'] = data['bio']
        if 'avatar_url' in data:
            update_data['avatar_url'] = data['avatar_url']
        if 'theme' in data:
            update_data['theme'] = data['theme']
        
        supabase.table('users').update(update_data).eq('id', user_id).execute()
        
        return jsonify({'message': 'User updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to update user: {str(e)}'}), 500

@app.route('/api/users/search', methods=['GET'])
@token_required
def search_users():
    """Search users by email or name"""
    try:
        query = request.args.get('q', '')
        
        if len(query) < 2:
            return jsonify({'message': 'Search query too short'}), 400
        
        # Search by email
        users = supabase.table('users').select('id, email, full_name, avatar_url, status').ilike('email', f'%{query}%').execute()
        
        if not users.data:
            # Search by name
            users = supabase.table('users').select('id, email, full_name, avatar_url, status').ilike('full_name', f'%{query}%').execute()
        
        return jsonify(users.data), 200
        
    except Exception as e:
        return jsonify({'message': f'Search failed: {str(e)}'}), 500

# ==================== CONVERSATION ENDPOINTS ====================

@app.route('/api/conversations', methods=['GET'])
@token_required
def get_conversations():
    """Get user's conversations"""
    try:
        # Get conversations where user is a member
        conversations = supabase.table('conversation_members').select('conversation_id').eq('user_id', request.user_id).execute()
        
        conv_ids = [conv['conversation_id'] for conv in conversations.data]
        
        if not conv_ids:
            return jsonify([]), 200
        
        # Get conversation details
        conv_details = supabase.table('conversations').select('*').in_('id', conv_ids).order('updated_at', desc=True).execute()
        
        result = []
        for conv in conv_details.data:
            members = supabase.table('conversation_members').select('user_id').eq('conversation_id', conv['id']).execute()
            last_message = supabase.table('messages').select('content, created_at, sender_id').eq('conversation_id', conv['id']).order('created_at', desc=True).limit(1).execute()
            
            conv['members'] = [m['user_id'] for m in members.data]
            conv['last_message'] = last_message.data[0] if last_message.data else None
            
            result.append(conv)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to get conversations: {str(e)}'}), 500

@app.route('/api/conversations', methods=['POST'])
@token_required
def create_conversation():
    """Create new conversation"""
    try:
        data = request.get_json()
        participant_ids = data.get('participant_ids', [])
        
        if not participant_ids:
            return jsonify({'message': 'Participant IDs required'}), 400
        
        # Add current user to participants
        if request.user_id not in participant_ids:
            participant_ids.append(request.user_id)
        
        # Create conversation
        conv_data = {
            'title': data.get('title'),
            'is_group': len(participant_ids) > 2,
            'created_by': request.user_id
        }
        conversation = supabase.table('conversations').insert(conv_data).execute()
        conv_id = conversation.data[0]['id']
        
        # Add members
        for user_id in participant_ids:
            member_data = {
                'conversation_id': conv_id,
                'user_id': user_id
            }
            supabase.table('conversation_members').insert(member_data).execute()
        
        return jsonify({
            'message': 'Conversation created',
            'conversation_id': conv_id
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Failed to create conversation: {str(e)}'}), 500

@app.route('/api/conversations/<conv_id>/messages', methods=['GET'])
@token_required
def get_messages(conv_id):
    """Get messages in conversation"""
    try:
        # Check if user is member
        member_check = supabase.table('conversation_members').select('id').eq('conversation_id', conv_id).eq('user_id', request.user_id).execute()
        
        if not member_check.data:
            return jsonify({'message': 'Unauthorized'}), 403
        
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        messages = supabase.table('messages').select('*').eq('conversation_id', conv_id).eq('is_deleted', False).order('created_at', desc=False).range(offset, offset + limit - 1).execute()
        
        return jsonify(messages.data), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to get messages: {str(e)}'}), 500

@app.route('/api/conversations/<conv_id>/messages', methods=['POST'])
@token_required
def send_message(conv_id):
    """Send message"""
    try:
        # Check if user is member
        member_check = supabase.table('conversation_members').select('id').eq('conversation_id', conv_id).eq('user_id', request.user_id).execute()
        
        if not member_check.data:
            return jsonify({'message': 'Unauthorized'}), 403
        
        data = request.get_json()
        
        message_data = {
            'conversation_id': conv_id,
            'sender_id': request.user_id,
            'content': data.get('content'),
            'message_type': data.get('message_type', 'text'),
            'media_url': data.get('media_url'),
            'media_name': data.get('media_name'),
            'media_size': data.get('media_size'),
            'media_duration': data.get('media_duration'),
            'location_latitude': data.get('location_latitude'),
            'location_longitude': data.get('location_longitude'),
            'location_address': data.get('location_address')
        }
        
        message = supabase.table('messages').insert(message_data).execute()
        msg_id = message.data[0]['id']
        
        # Add receipts
        members = supabase.table('conversation_members').select('user_id').eq('conversation_id', conv_id).execute()
        for member in members.data:
            receipt_data = {
                'message_id': msg_id,
                'user_id': member['user_id'],
                'status': 'sent' if member['user_id'] != request.user_id else 'read',
                'delivered_at': datetime.utcnow().isoformat() if member['user_id'] != request.user_id else None,
                'read_at': datetime.utcnow().isoformat() if member['user_id'] == request.user_id else None
            }
            supabase.table('message_receipts').insert(receipt_data).execute()
        
        # Update conversation
        supabase.table('conversations').update({'updated_at': datetime.utcnow().isoformat()}).eq('id', conv_id).execute()
        
        # Create notification for members
        for member in members.data:
            if member['user_id'] != request.user_id:
                notification_data = {
                    'user_id': member['user_id'],
                    'type': 'message',
                    'related_user_id': request.user_id,
                    'message_id': msg_id,
                    'title': f'New message in conversation',
                    'body': data.get('content', '[Media]')
                }
                supabase.table('notifications').insert(notification_data).execute()
        
        return jsonify(message.data[0]), 201
        
    except Exception as e:
        return jsonify({'message': f'Failed to send message: {str(e)}'}), 500

@app.route('/api/messages/<msg_id>/read', methods=['PUT'])
@token_required
def mark_message_read(msg_id):
    """Mark message as read"""
    try:
        supabase.table('message_receipts').update({
            'status': 'read',
            'read_at': datetime.utcnow().isoformat()
        }).eq('message_id', msg_id).eq('user_id', request.user_id).execute()
        
        return jsonify({'message': 'Message marked as read'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to mark as read: {str(e)}'}), 500

# ==================== CALL ENDPOINTS ====================

@app.route('/api/calls', methods=['POST'])
@token_required
def initiate_call():
    """Initiate voice or video call"""
    try:
        data = request.get_json()
        conversation_id = data.get('conversation_id')
        call_type = data.get('call_type')  # 'voice' or 'video'
        
        if not conversation_id or not call_type:
            return jsonify({'message': 'Conversation ID and call type required'}), 400
        
        # Generate Jitsi room ID
        jitsi_room_id = f"chat-{str(uuid.uuid4())[:8]}"
        
        call_data = {
            'conversation_id': conversation_id,
            'caller_id': request.user_id,
            'call_type': call_type,
            'status': 'initiated',
            'jitsi_room_id': jitsi_room_id
        }
        
        call = supabase.table('calls').insert(call_data).execute()
        call_id = call.data[0]['id']
        
        # Get conversation members
        members = supabase.table('conversation_members').select('user_id').eq('conversation_id', conversation_id).execute()
        
        # Add participants (except caller)
        for member in members.data:
            if member['user_id'] != request.user_id:
                participant_data = {
                    'call_id': call_id,
                    'user_id': member['user_id'],
                    'status': 'pending'
                }
                supabase.table('call_participants').insert(participant_data).execute()
                
                # Send notification
                notification_data = {
                    'user_id': member['user_id'],
                    'type': 'call',
                    'related_user_id': request.user_id,
                    'call_id': call_id,
                    'title': f'Incoming {call_type} call',
                    'body': 'Someone is calling you'
                }
                supabase.table('notifications').insert(notification_data).execute()
        
        return jsonify({
            'call_id': call_id,
            'jitsi_room_id': jitsi_room_id
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Failed to initiate call: {str(e)}'}), 500

@app.route('/api/calls/<call_id>/accept', methods=['PUT'])
@token_required
def accept_call(call_id):
    """Accept incoming call"""
    try:
        # Update participant status
        supabase.table('call_participants').update({
            'status': 'accepted',
            'joined_at': datetime.utcnow().isoformat()
        }).eq('call_id', call_id).eq('user_id', request.user_id).execute()
        
        # Update call status
        supabase.table('calls').update({'status': 'active'}).eq('id', call_id).execute()
        
        return jsonify({'message': 'Call accepted'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to accept call: {str(e)}'}), 500

@app.route('/api/calls/<call_id>/reject', methods=['PUT'])
@token_required
def reject_call(call_id):
    """Reject incoming call"""
    try:
        supabase.table('call_participants').update({
            'status': 'rejected'
        }).eq('call_id', call_id).eq('user_id', request.user_id).execute()
        
        return jsonify({'message': 'Call rejected'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to reject call: {str(e)}'}), 500

@app.route('/api/calls/<call_id>/end', methods=['PUT'])
@token_required
def end_call(call_id):
    """End call"""
    try:
        call_result = supabase.table('calls').select('*').eq('id', call_id).execute()
        
        if not call_result.data:
            return jsonify({'message': 'Call not found'}), 404
        
        call = call_result.data[0]
        started = datetime.fromisoformat(call['started_at']) if call['started_at'] else datetime.utcnow()
        duration = int((datetime.utcnow() - started).total_seconds())
        
        supabase.table('calls').update({
            'status': 'completed',
            'ended_at': datetime.utcnow().isoformat(),
            'duration_seconds': duration
        }).eq('id', call_id).execute()
        
        supabase.table('call_participants').update({
            'left_at': datetime.utcnow().isoformat()
        }).eq('call_id', call_id).eq('user_id', request.user_id).execute()
        
        return jsonify({'message': 'Call ended'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to end call: {str(e)}'}), 500

# ==================== FRIENDSHIP ENDPOINTS ====================

@app.route('/api/friendships/request', methods=['POST'])
@token_required
def send_friend_request():
    """Send friend request"""
    try:
        data = request.get_json()
        user_id_2 = data.get('user_id')
        
        if not user_id_2:
            return jsonify({'message': 'User ID required'}), 400
        
        if user_id_2 == request.user_id:
            return jsonify({'message': 'Cannot send request to yourself'}), 400
        
        # Check if already friends or request exists
        existing = supabase.table('friendships').select('id').eq('user_id_1', request.user_id).eq('user_id_2', user_id_2).execute()
        
        if existing.data:
            return jsonify({'message': 'Friendship or request already exists'}), 409
        
        friendship_data = {
            'user_id_1': request.user_id,
            'user_id_2': user_id_2,
            'requested_by': request.user_id,
            'status': 'pending'
        }
        
        supabase.table('friendships').insert(friendship_data).execute()
        
        # Send notification
        notification_data = {
            'user_id': user_id_2,
            'type': 'friend_request',
            'related_user_id': request.user_id,
            'title': 'Friend request received',
            'body': 'Someone sent you a friend request'
        }
        supabase.table('notifications').insert(notification_data).execute()
        
        return jsonify({'message': 'Friend request sent'}), 201
        
    except Exception as e:
        return jsonify({'message': f'Failed to send request: {str(e)}'}), 500

@app.route('/api/friendships/<friendship_id>/accept', methods=['PUT'])
@token_required
def accept_friend_request(friendship_id):
    """Accept friend request"""
    try:
        supabase.table('friendships').update({'status': 'accepted'}).eq('id', friendship_id).execute()
        
        # Get friendship details
        friendship = supabase.table('friendships').select('*').eq('id', friendship_id).execute()
        requester_id = friendship.data[0]['requested_by']
        
        # Send notification
        notification_data = {
            'user_id': requester_id,
            'type': 'friend_accepted',
            'related_user_id': request.user_id,
            'title': 'Friend request accepted',
            'body': 'Your friend request was accepted'
        }
        supabase.table('notifications').insert(notification_data).execute()
        
        return jsonify({'message': 'Friend request accepted'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to accept request: {str(e)}'}), 500

@app.route('/api/friends', methods=['GET'])
@token_required
def get_friends():
    """Get user's friends"""
    try:
        friendships = supabase.table('friendships').select('*').eq('status', 'accepted').execute()
        
        friends = []
        for friendship in friendships.data:
            if friendship['user_id_1'] == request.user_id:
                friends.append(friendship['user_id_2'])
            elif friendship['user_id_2'] == request.user_id:
                friends.append(friendship['user_id_1'])
        
        # Get friend details
        friend_details = []
        for friend_id in friends:
            user = supabase.table('users').select('id, email, full_name, avatar_url, status').eq('id', friend_id).execute()
            if user.data:
                friend_details.append(user.data[0])
        
        return jsonify(friend_details), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to get friends: {str(e)}'}), 500

# ==================== NOTIFICATION ENDPOINTS ====================

@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications():
    """Get user notifications"""
    try:
        limit = request.args.get('limit', 50, type=int)
        only_unread = request.args.get('unread', 'false').lower() == 'true'
        
        query = supabase.table('notifications').select('*').eq('user_id', request.user_id)
        
        if only_unread:
            query = query.eq('is_read', False)
        
        notifications = query.order('created_at', desc=True).limit(limit).execute()
        
        return jsonify(notifications.data), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to get notifications: {str(e)}'}), 500

@app.route('/api/notifications/<notif_id>/read', methods=['PUT'])
@token_required
def mark_notification_read(notif_id):
    """Mark notification as read"""
    try:
        supabase.table('notifications').update({
            'is_read': True,
            'read_at': datetime.utcnow().isoformat()
        }).eq('id', notif_id).eq('user_id', request.user_id).execute()
        
        return jsonify({'message': 'Notification marked as read'}), 200
        
    except Exception as e:
        return jsonify({'message': f'Failed to mark notification: {str(e)}'}), 500

# ==================== MEDIA ENDPOINTS ====================

@app.route('/api/media/upload', methods=['POST'])
@token_required
def upload_media():
    """Upload media file"""
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'File required'}), 400
        
        file = request.files['file']
        conversation_id = request.form.get('conversation_id')
        
        if not file or not conversation_id:
            return jsonify({'message': 'File and conversation ID required'}), 400
        
        # Check if user is member of conversation
        member_check = supabase.table('conversation_members').select('id').eq('conversation_id', conversation_id).eq('user_id', request.user_id).execute()
        
        if not member_check.data:
            return jsonify({'message': 'Unauthorized'}), 403
        
        # Upload to Supabase Storage
        file_name = f"{request.user_id}/{uuid.uuid4()}/{file.filename}"
        file_path = f"chat-media/{file_name}"
        
        supabase.storage.from_('chat-bucket').upload(
            file_path,
            file.read()
        )
        
        # Get public URL
        file_url = supabase.storage.from_('chat-bucket').get_public_url(file_path)
        
        # Save media info to database
        media_data = {
            'user_id': request.user_id,
            'file_name': file.filename,
            'file_type': file.content_type,
            'file_size': file.content_length,
            'file_url': file_url,
            'file_path': file_path
        }
        
        media = supabase.table('media_files').insert(media_data).execute()
        
        return jsonify({
            'media_id': media.data[0]['id'],
            'file_url': file_url,
            'file_name': file.filename
        }), 201
        
    except Exception as e:
        return jsonify({'message': f'Failed to upload media: {str(e)}'}), 500

# ==================== HELPER FUNCTIONS ====================

def send_verification_email(email, token, user_id):
    """Send email verification link"""
    # Implement with your email service (SendGrid, AWS SES, etc.)
    verification_link = f"{FRONTEND_URL}/verify-email?token={token}&user_id={user_id}"
    print(f"Verification link: {verification_link}")
    # Send email here

def send_password_reset_email(email, token, user_id):
    """Send password reset link"""
    # Implement with your email service
    reset_link = f"{FRONTEND_URL}/reset-password?token={token}&user_id={user_id}"
    print(f"Reset link: {reset_link}")
    # Send email here

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'message': 'Server error'}), 500

# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

# ==================== MAIN ====================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
