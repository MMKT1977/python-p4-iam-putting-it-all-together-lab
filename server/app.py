#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        required_fields = ['username', 'password']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return {'errors': {field: f"{field} is required" for field in missing_fields}}, 422
        
        try:
            new_user = User(
                username=data['username'],
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
    
            new_user.password_hash = data['password']
            
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            
            return {
                'id': new_user.id,
                'username': new_user.username,
                'image_url': new_user.image_url,
                'bio': new_user.bio
            }, 201
            
        except IntegrityError:
            db.session.rollback()
            return {'errors': {'username': 'Username already taken'}}, 422
            
        except ValueError as e:
            db.session.rollback()
            return {'errors': str(e)}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'error': 'Unauthorized'}, 401
            
        user = User.query.filter(User.id == user_id).first()
        
        if not user:
            return {'error': 'User not found'}, 404
            
        return {
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }, 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        
        required_fields = ['username', 'password']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return {'errors': {field: f"{field} is required" for field in missing_fields}}, 401
        
        user = User.query.filter(User.username == data['username']).first()
    
        if not user or not user.authenticate(data['password']):
            return {'error': 'Invalid username or password'}, 401
        
        session['user_id'] = user.id
        
        return {
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }, 200

class Logout(Resource):
    def delete(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
    
        session.pop('user_id')
        return '', 204

class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401

        recipes = Recipe.query.all()
        
        recipes_data = [{
            'id': recipe.id,
            'title': recipe.title,
            'instructions': recipe.instructions,
            'minutes_to_complete': recipe.minutes_to_complete,
            'user': {
                'id': recipe.user.id,
                'username': recipe.user.username,
                'image_url': recipe.user.image_url,
                'bio': recipe.user.bio
            }
        } for recipe in recipes]
        
        return recipes_data, 200

    def post(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401

        data = request.get_json()
        user = User.query.get(session['user_id'])

        try:
            new_recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user.id
            )

            db.session.add(new_recipe)
            db.session.commit()

            return {
                'id': new_recipe.id,
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
            }, 201

        except IntegrityError as e:
            db.session.rollback()
            return {'errors': ['Validation error']}, 422

        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        except KeyError as e:
            db.session.rollback()
            return {'errors': [f"{e.args[0]} is required"]}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)