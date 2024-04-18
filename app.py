from aiohttp import web
from sqlalchemy import Column, Integer, String, DateTime, create_engine, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import jwt
import os



Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Advertisement(Base):
    __tablename__ = 'advertisements'

    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(String(500), nullable=False)
    creation_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    owner = relationship('User', backref='advertisements')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'creation_date': self.creation_date.isoformat(),
            'owner_id': self.owner_id
        }

# Creating DB Engine
engine = create_engine('sqlite:///advertisements.db')

# Creating all tables
Base.metadata.create_all(engine)

# Creating Session
Session = sessionmaker(bind=engine)

# Фиксированный токен
FIXED_TOKEN = '55555'

# Функция для создания токена (больше не принимает user_id)
def create_token():
    payload = {
        'user_id': FIXED_TOKEN  # Используем фиксированный токен
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')


# Middleware для аутентификации пользователей
@web.middleware
async def auth_middleware(request, handler):
    request.user = None
    jwt_token = request.headers.get('Authorization', None)
    if jwt_token:
        try:
            scheme, token = jwt_token.split()
            if scheme.lower() != 'bearer':
                raise ValueError('Invalid authorization scheme')
            # Вместо декодирования токена, проверяем фиксированный токен
            if token != FIXED_TOKEN:
                raise ValueError('Invalid token')
            # Устанавливаем фиксированный user_id
            request.user = FIXED_TOKEN
        except (ValueError):
            return web.json_response({'message': 'Token is invalid'}, status=400)
    return await handler(request)


# Routes
routes = web.RouteTableDef()


# Изменяем создание токена в функциях register и login
@routes.post('/register')
async def register(request):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')

    session = Session()
    existing_user = session.query(User).filter_by(username=username).first()
    if existing_user:
        return web.json_response({'message': 'Username already exists'}, status=400)

    new_user = User(username=username)
    new_user.set_password(password)
    session.add(new_user)
    session.commit()

    # Генерируем фиксированный токен
    token = FIXED_TOKEN
    return web.json_response({'message': 'User created successfully', 'token': token}, status=201)

 
@routes.post('/login')
async def login(request):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')

    session = Session()
    user = session.query(User).filter_by(username=username).first()
    if user and user.check_password(password):
        # Генерируем фиксированный токен
        token = FIXED_TOKEN
        return web.json_response({'message': 'Login successful', 'token': token})
    else:
        return web.json_response({'message': 'Invalid username or password'}, status=401)



@routes.post('/advertisements')
async def create_advertisement(request):
    data = await request.json()
    title = data.get('title')
    description = data.get('description')

    if not request.user:
        return web.json_response({'message': 'Authentication required'}, status=401)

    session = Session()
    advertisement = Advertisement(title=title, description=description, owner_id=FIXED_TOKEN)
    session.add(advertisement)
    session.commit()
    return web.json_response({'message': 'Advertisement created successfully', 'advertisement': advertisement.to_dict()}, status=201)



@routes.get('/advertisements/{id}')
async def get_advertisement(request):
    advertisement_id = request.match_info['id']
    session = Session()
    advertisement = session.get(Advertisement, advertisement_id)
    if advertisement:
        return web.json_response({'advertisement': advertisement.to_dict()})
    else:
        return web.json_response({'message': 'Advertisement not found'}, status=404)
    

@routes.get('/advertisements')
async def get_all_advertisements(request):
    # Проверяем наличие токена
    if request.user != FIXED_TOKEN:
        return web.json_response({'message': 'Authentication required'}, status=401)
    
    session = Session()
    advertisements = session.query(Advertisement).all()
    advertisements_data = [advertisement.to_dict() for advertisement in advertisements]
    return web.json_response({'advertisements': advertisements_data})


@routes.delete('/advertisements/{id}')
async def delete_advertisement(request):
    advertisement_id = request.match_info['id']
    session = Session()
    advertisement = session.get(Advertisement, advertisement_id)

    if not advertisement:
        return web.json_response({'message': 'Advertisement not found'}, status=404)

    if int(advertisement.owner_id) != int(request.user):
        return web.json_response({'message': 'You are not the owner of this advertisement'}, status=403)

    session.delete(advertisement)
    session.commit()
    return web.json_response({'message': 'Advertisement deleted successfully'})



# Создание приложения и применение middleware
app = web.Application(middlewares=[auth_middleware])
app.add_routes(routes)


# Запуск приложения
if __name__ == '__main__':
 
    web.run_app(app, port=5000)