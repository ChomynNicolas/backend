# app/routes.py
from flask import request, jsonify
import bcrypt
from app import db
from app.models import User, Room, Booking
from flask import Blueprint

api = Blueprint('api', __name__)


@api.route('/api/users', methods=['POST'])
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

@api.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'name': user.name, 'email': user.email} for user in users])

# Rutas para habitaciones
@api.route('/api/rooms', methods=['POST'])
def create_room():
    data = request.get_json()
    new_room = Room(number=data['number'], type=data['type'], price=data['price'])
    db.session.add(new_room)
    db.session.commit()
    return jsonify({'message': 'Room created'}), 201

@api.route('/api/rooms', methods=['GET'])
def get_rooms():
    rooms = Room.query.all()
    return jsonify([{'id': room.id, 'number': room.number, 'type': room.type, 'price': str(room.price)} for room in rooms])

# Rutas para reservaciones
@api.route('/api/bookings', methods=['POST'])
def create_booking():
    data = request.get_json()
    new_booking = Booking(user_id=data['user_id'], room_id=data['room_id'], check_in_date=data['check_in_date'], check_out_date=data['check_out_date'])
    db.session.add(new_booking)
    db.session.commit()
    return jsonify({'message': 'Booking created'}), 201

@api.route('/api/bookings', methods=['GET'])
def get_bookings():
    bookings = Booking.query.all()
    return jsonify([{'id': booking.id, 'user_id': booking.user_id, 'room_id': booking.room_id,
                     'check_in_date': booking.check_in_date, 'check_out_date': booking.check_out_date, 
                     'status': booking.status} for booking in bookings])

