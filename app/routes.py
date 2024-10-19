from flask import request, jsonify
import bcrypt
from app import db
from app.models import User, Room, Booking
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask import Blueprint
import datetime

api = Blueprint('api', __name__)

### RUTAS PARA USUARIOS ###

@api.route('/api/register', methods=['POST'])
def create_user():
    data = request.get_json()
    
    existing_user = User.query.filter_by(email=data['email']).first()
    
    if existing_user:
        return jsonify({'error': 'Email already exists'}), 400
    
    password = data['password'].encode('utf-8')
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt(rounds=8)).decode('utf-8')
    
    new_user = User(name=data['name'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created'}), 201

@api.route('/api/login', methods=['POST'])
def login_user():
    data = request.get_json()
    existing_user = User.query.filter_by(email=data['email']).first()
    
    if not existing_user:
        return jsonify({'error': 'Invalid email or password'}), 400

    password = data['password'].encode('utf-8')
    stored_password = existing_user.password.encode('utf-8')
    
    if bcrypt.checkpw(password, stored_password):
        access_token = create_access_token(identity={'email': existing_user.email}, expires_delta=datetime.timedelta(hours=6))
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 400

@api.route('/api/rooms/availability', methods=['POST'])
def check_room_availability():
    data = request.get_json()
    check_in_date = datetime.datetime.strptime(data['check_in_date'], '%Y-%m-%d')
    check_out_date = datetime.datetime.strptime(data['check_out_date'], '%Y-%m-%d')

    if check_in_date >= check_out_date:
        return jsonify({'error': 'Invalid date range. Check-out date must be after check-in date.'}), 400

    room_number = data.get('room_number')
    booked_rooms = Booking.query.filter(
        (Booking.check_in_date < check_out_date) & 
        (Booking.check_out_date > check_in_date)
    ).all()

    booked_room_ids = [booking.room_id for booking in booked_rooms]

    if room_number:
        room = Room.query.filter_by(number=room_number).first()
        if not room:
            return jsonify({'error': f'Room with number {room_number} does not exist.'}), 404
        
        if room.id in booked_room_ids:
            return jsonify({'message': f'Room {room_number} is not available for the selected dates.'}), 200
        else:
            return jsonify({'message': f'Room {room_number} is available for the selected dates.'}), 200
    else:
        available_rooms = Room.query.filter(~Room.id.in_(booked_room_ids)).all()
        if available_rooms:
            return jsonify([{'id': room.id, 'number': room.number, 'type': room.type, 'price': str(room.price)} for room in available_rooms]), 200
        else:
            return jsonify({'message': 'No rooms available for the selected dates.'}), 200

@api.route('/api/bookings/user/<int:user_id>', methods=['GET'])
@jwt_required()  
def get_user_bookings(user_id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if current_user['email'] != user.email:
        return jsonify({'error': 'Unauthorized access to bookings'}), 403

    bookings = Booking.query.filter_by(user_id=user_id).all()

    if bookings:
        return jsonify([
            {
                'id': booking.id,
                'room_id': booking.room_id,
                'check_in_date': booking.check_in_date.strftime('%Y-%m-%d'),
                'check_out_date': booking.check_out_date.strftime('%Y-%m-%d'),
                'status': booking.status
            }
            for booking in bookings
        ]), 200
    else:
        return jsonify({'message': 'No bookings found for this user.'}), 200

@api.route('/api/bookings/<int:booking_id>/cancel', methods=['PUT'])
@jwt_required()
def cancel_booking(booking_id):
    current_user = get_jwt_identity()
    booking = Booking.query.filter_by(id=booking_id).first()
    
    if not booking:
        return jsonify({'error': 'Booking not found'}), 404

    user = User.query.filter_by(id=booking.user_id).first()
    if current_user['email'] != user.email:
        return jsonify({'error': 'Unauthorized to cancel this booking'}), 403
    
    if booking.status == 'canceled':
        return jsonify({'message': 'Booking is already canceled'}), 400

    booking.status = 'canceled'
    db.session.commit()
    
    return jsonify({'message': 'Booking canceled successfully'}), 200


### RUTAS PARA ADMINISTRADORES ###

@api.route('/api/users', methods=['GET'])
@jwt_required()  
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'name': user.name, 'email': user.email} for user in users])

@api.route('/api/rooms', methods=['POST'])
@jwt_required()  
def create_room():
    data = request.get_json()
    new_room = Room(number=data['number'], type=data['type'], price=data['price'])
    db.session.add(new_room)
    db.session.commit()
    return jsonify({'message': 'Room created'}), 201

@api.route('/api/rooms/<int:room_id>/update', methods=['PUT'])
@jwt_required()  
def update_room(room_id):
    data = request.get_json()
    
    room = Room.query.get(room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    if 'number' in data:
        room.number = data['number']
    
    if 'type' in data:
        room.type = data['type']
    
    if 'price' in data:
        room.price = data['price']
    
    if 'status' in data:
        if data['status'] not in ['available', 'occupied']:
            return jsonify({'error': 'Invalid status value'}), 400
        room.status = data['status']
    
    db.session.commit()
    return jsonify({'message': 'Room updated successfully'}), 200

@api.route('/api/bookings', methods=['GET'])
@jwt_required()  
def get_bookings():
    bookings = Booking.query.all()
    return jsonify([{
        'id': booking.id, 
        'user_id': booking.user_id, 
        'room_id': booking.room_id,
        'check_in_date': booking.check_in_date, 
        'check_out_date': booking.check_out_date, 
        'status': booking.status} 
        for booking in bookings])
