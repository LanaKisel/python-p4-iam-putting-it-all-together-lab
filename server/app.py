#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        image_url = json.get('image_url')
        bio = json.get('bio')

        user = User(
            username = username,
            image_url = image_url,
            bio = bio
        )
        user.password_hash = password

        try:
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            return {'error':'422 Unprocessable Entity'}, 422        

class CheckSession(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter(User.id == session['user_id']).first()
            return user.to_dict(), 200
        return {'error':'401 Unauthorized'}, 401    

class Login(Resource):
    def post(self):
        username = request.get_json()['username']
        user = User.query.filter(User.username == username).first()

        password = request.get_json()['password']
        if user:
            if user.authenticate(password):
                session['user_id']=user.id
                return user.to_dict(), 201
        return {'error':'401 Unauthorized'}, 401    



class Logout(Resource):
    def delete(self):
        #      if no function app.before_request
        # if session.get('user_id'):
        #     session['user_id'] = None
        #     return {}, 204
        # return {'error': '401 User is not logged in'}, 401    
        
        session['user_id'] = None
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        # if session.get('user_id'):
        user = User.query.filter(User.id == session['user_id']).first()
        return [recipe.to_dict() for recipe in user.recipes], 200
        # return {'error':'Unauthorized'}, 401    

    def post(self):
        new_recipe_title = request.get_json()['title']
        new_recipe_instructions = request.get_json()['instructions']
        new_recipe_minutes_to_complete = request.get_json()['minutes_to_complete']

        try:
            new_recipe = Recipe(
                title = new_recipe_title,
                instructions = new_recipe_instructions,
                minutes_to_complete = new_recipe_minutes_to_complete,
                user_id = session['user_id']
            )
            db.session.add(new_recipe)
            db.session.commit()

            return new_recipe.to_dict(), 201
        except IntegrityError:
            return {'error':'422 Unprocessable Entity'}, 422    


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)