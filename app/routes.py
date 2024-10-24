from flask import request, jsonify
import bcrypt
from app import db
from app.models import User, Room, Booking
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask import Blueprint
import datetime

api = Blueprint('api', __name__)


def room_to_dict(room):
    return {
        'id': room.id,
        'number': room.number,
        'type': room.type,
        'price': room.price,
        'status': room.status
    }


### RUTAS PARA USUARIOS ###

@api.route('/api/register', methods=['POST'])
def create_user():
    data = request.get_json()
    
    existing_user = User.query.filter_by(email=data['email']).first()
    
    if existing_user:
        return jsonify({'error': 'El email ya tiene una cuenta'}), 400
    
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
        return jsonify({'error': 'El correo no está registrado'}), 400

    password = data['password'].encode('utf-8')
    stored_password = existing_user.password.encode('utf-8')
    
    if bcrypt.checkpw(password, stored_password):
        access_token = create_access_token(identity={'email': existing_user.email}, expires_delta=datetime.timedelta(hours=6))
        return jsonify({'access_token': access_token,'role': existing_user.role}), 200
    else:
        return jsonify({'error': 'La contraseña es incorrecta'}), 400
    
    
@api.route('/api/user/role', methods=['GET'])
@jwt_required()  # Asegura que el usuario está autenticado
def get_user_role():
    # Obtener la identidad del token JWT (email en este caso)
    current_user_email = get_jwt_identity()
    
    # Buscar al usuario por email
    user = User.query.filter_by(email=current_user_email['email']).first()
    
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    
    # Retornar el rol del usuario
    return jsonify({'role': user.role}), 200

@api.route('/api/rooms/availability', methods=['POST'])
def check_room_availability():
    data = request.get_json()
    check_in_date = datetime.datetime.fromisoformat(data['check_in_date'].replace('Z', ''))
    check_out_date = datetime.datetime.fromisoformat(data['check_out_date'].replace('Z', ''))

    if check_in_date >= check_out_date:
        return jsonify({'error': 'Intervalo de fechas no válido. La fecha de salida debe ser posterior a la fecha de entrada.'}), 400

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
            return jsonify({'message': f'Habitación {room_number} no está disponible en las fechas seleccionadas.', "isAvailable":False}), 200
        else:
            return jsonify({'message': f'Habitación {room_number} está disponible en las fechas seleccionadas.', "isAvailable":True}), 200
    else:
        available_rooms = Room.query.filter(~Room.id.in_(booked_room_ids)).all()
        if available_rooms:
            return jsonify([{'id': room.id, 'number': room.number, 'type': room.type, 'price': str(room.price)} for room in available_rooms]), 200
        else:
            return jsonify({'message': 'No rooms available for the selected dates.'}), 200

@api.route('/api/bookings', methods=['POST'])
@jwt_required()
def create_booking():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    
    data = request.get_json()
    room_id = data.get('room_id')
    check_in_date = datetime.datetime.fromisoformat(data['check_in_date'].replace('Z', ''))
    check_out_date = datetime.datetime.fromisoformat(data['check_out_date'].replace('Z', ''))
    
    # Validacion de fechas
    if check_in_date >= check_out_date:
        return jsonify({'error': 'La fecha de salida debe ser posterior a la fecha de entrada. '}), 400
    
    # Verificar que la habitación existe
    room = Room.query.get(room_id)
    if not room:
        return jsonify({'error': f'La habitación con id {room_id} no existe.'}),
    404
    
    #Comprobar si la habitación está disponible en las fechas solicitadas
    existings_bookings = Booking.query.filter(
        (Booking.room_id == room_id) & (Booking.check_in_date < check_out_date) & (Booking.check_out_date > check_in_date)
    ).all()
    
    if existings_bookings:
        return jsonify({'error': f'La habitación {room.number} no está disponible para las fechas seleccionadas. '}),400
    
    # Crear la nueva reserva
    new_booking = Booking(
        user_id=user.id,
        room_id=room_id,
        check_in_date=check_in_date,
        check_out_date=check_out_date,
        status="reserved"
    )
    
    db.session.add(new_booking)
    db.session.commit()
    
    return jsonify({'message': 'Reservación creada con éxito'}),201

@api.route('/api/bookings/user', methods=['GET'])  
@jwt_required()  
def get_user_bookings():
    current_user = get_jwt_identity()  
    user = User.query.filter_by(email=current_user['email']).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    
    bookings = Booking.query.filter_by(user_id=user.id).all()

    if bookings:
        return jsonify([{
                'id': booking.id,
                'room_id': booking.room_id,
                'check_in_date': booking.check_in_date.strftime('%Y-%m-%d'),
                'check_out_date': booking.check_out_date.strftime('%Y-%m-%d'),
                'status': booking.status
            } for booking in bookings
        ]), 200
    else:
        return jsonify({'message': 'No se encontraron reservaciones.'}), 200

@api.route('/api/bookings/user/<int:user_id>', methods=['GET'])
@jwt_required()  
def get_user_bookingsById(user_id):
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


@api.route('/api/rooms', methods=['GET'])
def get_rooms():
    rooms = Room.query.all()  
    return jsonify([{
        'id': room.id,
        'number': room.number,
        'type': room.type,
        'price': str(room.price),
        'status': room.status
    } for room in rooms]), 200 


### RUTAS PARA ADMINISTRADORES ###

@api.route('/api/users', methods=['GET'])
@jwt_required()  
def get_users():
    users = User.query.all()
    return jsonify([{'id': user.id, 'name': user.name, 'email': user.email} for user in users])

@api.route('/api/rooms', methods=['POST'])
def create_room():
    data = request.get_json()

    
    new_room = Room(number=data['number'], type=data['type'], price=data['price'])

    
    db.session.add(new_room)
    db.session.commit()

    
    return jsonify(room_to_dict(new_room)), 201


@api.route('/api/rooms/<int:room_id>/update', methods=['PUT'])
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
        if data['status'] not in ['available', 'unavailable']:
            return jsonify({'error': 'Invalid status value'}), 400
        room.status = data['status']
    
    db.session.commit()

    
    return jsonify(room_to_dict(room)), 200


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
