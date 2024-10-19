from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.secret_key = 'bakala'
    app.config.from_object('app.config.Config')
    
    jwt = JWTManager(app)

    # Inicializar extensiones
    db.init_app(app)
    migrate.init_app(app, db)

    # Importar y registrar las rutas
    with app.app_context():
        from app import routes  # Importar rutas
        app.register_blueprint(routes.api)  # Registrar el blueprint de rutas

        db.create_all()  # Crear tablas si no existen
        
        

    return app


