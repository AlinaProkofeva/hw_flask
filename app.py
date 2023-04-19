import os
from hashlib import md5
from flask import Flask, jsonify, request, session as flask_session
from flask.views import MethodView
from sqlalchemy.orm import sessionmaker
import pydantic
from typing import Type, Optional

from models import User, Advertisement, Token, engine, Base


app = Flask('__name__')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
Session = sessionmaker(bind=engine)
Base.metadata.create_all(bind=engine)


'======== Обработка ошибок ========================================='

class HttpError(Exception):
    def __init__(self, status_code: int, description: str | dict | list):
        self.status_code = status_code
        self.description = description

@app.errorhandler
def error_handler(error: HttpError):
    response = jsonify({'status': 'error', 'message': error.description})
    response.status_code = error.status_code
    return response


'================ Валидация ================================================='

def check_len(value, attribute, min_value):

    '''вспомогательная функция для проверки длины'''
    if len(value) < min_value:
        raise ValueError(f'{attribute} is too short, min_lenght = {min_value}')


class CreateUser(pydantic.BaseModel):

    email: str
    password: str

    @pydantic.validator('password')
    def validate_password(cls, value):
        check_len(value, 'password', 5)
        return value


class CreateAdvertisement(pydantic.BaseModel):

    title: str
    description: str
    # user_id: int

    @pydantic.validator('title')
    def validate_title(cls, value):
        check_len(value, 'title', 8)
        return value

    @pydantic.validator('description')
    def validate_description(cls, value):
        check_len(value, 'description', 5)
        return value

    # @pydantic.validator('user_id')
    # def validate_user_id(cls, value):
    #     with Session() as session:
    #         user = get_item(value, User, session)
    #         return value


class UpdateAdvertisement(pydantic.BaseModel):

    title: Optional[str]
    description: Optional[str]

    @pydantic.validator('title')
    def validate_title(cls, value):
        check_len(value, 'title', 8)
        return value

    @pydantic.validator('description')
    def validate_description(cls, value):
        check_len(value, 'description', 5)
        return value


def validate(input_data: dict, validation_model: Type[CreateUser] | Type[CreateAdvertisement]):
    try:
        model_item = validation_model(**input_data)
        return model_item.dict(exclude_none=True)
    except pydantic.ValidationError as err:
        raise HttpError(400, err.errors())


'======== Общение с БД и вспомогательные функции ============================='

def get_item(item_id: int | str, model: User | Advertisement, session: Session):

    '''получение объекта модели по его id'''
    item = session.get(model, item_id)
    if item is None:
        raise HttpError(404, f'object {model.__name__} id{item_id} not found')
    return item


def check_user_exists(input_email: str, session: Session):

    '''проверка на уникальность пользователя в базе'''
    user = session.query(User).filter(User.email == input_email).first()
    if user:
        raise HttpError(400, f'user with email "{input_email}" already exists')
    else:
        return True


def hash_password(input_password: str):
    hashed_password = md5(input_password.encode()).hexdigest()
    return hashed_password


def check_token_in_headers(session: Session, advertisement: Advertisement):

    '''Сверка токена из заголовка с токеном владельца редактируемого объявления.
    Пропускает дальше только если токен соответствует владельцу'''
    try:
        headers_token = request.headers.get('token')
        get_user_by_token = get_item(headers_token, Token, session)
        print(get_user_by_token.user.id)
        print(get_user_by_token.id)

        if advertisement.user_id == get_user_by_token.user_id:
            print(advertisement.user_id, get_user_by_token.user_id)
            print('сравним')
            return True
    except HttpError:
        raise HttpError(401, 'Действие разрешено только владельцу')


'======== Вьюхи ========================================='

@app.route('/', methods=['GET'])
def test():
    return jsonify({'hello': 'test1'})

@app.route('/login/', methods=['POST'])
def login():

    '''Для аутентификации пользователя при входе в программу'''
    input_data = request.json
    validated_data = validate(input_data, CreateUser)
    validated_data['password'] = hash_password(validated_data['password'])

    with Session() as session:
        try:
            user_in_db_by_email = session.query(User).filter(User.email == validated_data['email']).first()
            if user_in_db_by_email.password == validated_data['password']:
                flask_session['is_logged'] = user_in_db_by_email.email  # зальем в сессию признак is_logged при
                # прохождении аутентификации и запишем в значение email пользователя
                return jsonify({'success': f'Hello, {user_in_db_by_email.email}'})
            else:
                raise HttpError(401, 'Неверный логин/пароль')
        except AttributeError:
            raise HttpError(400, 'Такого пользователя не существует')


@app.route('/remember_token/', methods=['GET'])
def remember_token():

    '''Восстановление токена после успешной авторизации'''
    if flask_session.get('is_logged'):
        with Session() as session:
            user_in_db_by_email = session.query(User).filter(User.email == flask_session.get('is_logged')).first()
            needed_token = session.query(Token).filter(Token.user_id == user_in_db_by_email.id).first()
            return jsonify({'user': f'{flask_session.get("is_logged")}', 'token': needed_token.id})
    else:
        raise HttpError(401, 'Действие доступно только авторизованному пользователю')


class UserView(MethodView):

    def get(self, user_id: int):
        with Session() as session:
            user = get_item(user_id, User, session)
            return jsonify({'user_id': user.id, 'email': user.email, 'created_at': user.created_at,
                            'advertisements': f'{user.advs}'})

    def post(self):
        input_data = request.json
        validated_data = validate(input_data, CreateUser)
        validated_data['password'] = hash_password(validated_data['password'])
        with Session() as session:
            check_user_exists(validated_data['email'], session)
            new_user = User(**validated_data)
            session.add(new_user)
            session.commit()

            user_token = Token(user_id=new_user.id)  # создание токена при регистрации пользователя
            session.add(user_token)
            session.commit()
            return jsonify({'status OK': f'user id{new_user.id} created', 'token': f'{user_token.id}',
                            'WARNING': 'save your token for authorization!'})

    def delete(self, user_id: int):
        with Session() as session:
            user = get_item(user_id, User, session)
            session.delete(user)
            session.commit()
            return jsonify({'status': f'user id{user.id} deleted'})


class AdvertisementView(MethodView):

    def get(self, adv_id: int):
        with Session() as session:
            adv = get_item(adv_id, Advertisement, session)
            return jsonify({'adv_id': adv.id, 'title': adv.title, 'description': adv.description,
                            'created_at': adv.created_at, 'created_by': f'user{adv.user_id}, {adv.user.email}'})

    def post(self):
        input_data = request.json
        validated_data = validate(input_data, CreateAdvertisement)
        with Session() as session:
            try:
                headers_token = request.headers['token']
                auth_user = get_item(headers_token, Token, session)  # проставление владельца по токену авторизации
                validated_data['user_id'] = auth_user.user_id

                new_advertisement = Advertisement(**validated_data)
                session.add(new_advertisement)
                session.commit()
                return jsonify({'success': f'advertisement id{new_advertisement.id} created with title '
                                           f'"{new_advertisement.title}"'})
            except KeyError:
                raise HttpError(401, 'Создание объявление доступно только авторизованному пользователю')


    def patch(self, adv_id: int):
        input_data = request.json
        if 'user_id' in input_data:
            raise HttpError(400, 'Смена владельца объявления невозможна')
        validated_data = validate(input_data, UpdateAdvertisement)
        with Session() as session:
            adv = get_item(adv_id, Advertisement, session)
            check_token_in_headers(session, adv)  # сверка владельца
            for field, value in validated_data.items():
                setattr(adv, field, value)
            session.add(adv)
            session.commit()
            return jsonify({'success': f'advertisement id{adv.id} updated', 'new_data': f'{validated_data}'})

    def delete(self, adv_id: int):
        with Session() as session:
            adv = get_item(adv_id, Advertisement, session)
            check_token_in_headers(session, adv)  # сверка владельца
            session.delete(adv)
            session.commit()
            return jsonify({'success': f'advertisement {adv.id} deleted'})


'======== Маршрутизация ========================================='

app.add_url_rule('/user/<int:user_id>/', view_func=UserView.as_view('user'), methods=['GET', 'DELETE'])
app.add_url_rule('/register/', view_func=UserView.as_view('register_user'), methods=['POST'])
app.add_url_rule('/advertisement/', view_func=AdvertisementView.as_view('create_advertisement'), methods=['POST'])
app.add_url_rule('/advertisement/<int:adv_id>/', view_func=AdvertisementView.as_view('advertisement'),
                 methods=['GET', 'PATCH', 'DELETE'])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
