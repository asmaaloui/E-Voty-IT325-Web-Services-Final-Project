from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from passlib.hash import pbkdf2_sha256
import os
from datetime import timedelta
import smtplib
# Initialize the app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Configure the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'election.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database
db = SQLAlchemy(app)


    
# Initialize Marshmallow
ma = Marshmallow(app)

# Initialize Flask JWT extended
app.config['JWT_SECRET_KEY'] = "1234"
app.config["JWT_ALGORITHM"] = "HS256"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access']
jwt = JWTManager(app)

blacklist = set()

# Create the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    email = db.Column(db.String(100))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    governate = db.Column(db.String(100))
    electoral_circle = db.Column(db.String(100))
    voted = db.Column(db.Boolean)
    role = db.Column(db.String(100))

# Create the User schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password', 'email', 'first_name', 'last_name', 'governate', 'electoral_circle', 'voted', 'role')

# Initialize the User schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Create the Candidate model
class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    governate = db.Column(db.String(100))
    electoral_circle = db.Column(db.String(100))

# Create the Candidate schema
class CandidateSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'governate', 'electoral_circle')

# Initialize the Candidate schema
candidate_schema = CandidateSchema()
candidates_schema = CandidateSchema(many=True)

# Create the tables in the database
@app.before_first_request
def create_tables():
    db.create_all()

#def send_confirmation_email(to_email, candidate_name):
    # Set up the SMTP server
#    server = smtplib.SMTP('smtp.gmail.com', 587)
#    server.starttls()
#    server.login('asmaaloui112@gmail.com', 'udndfudtkrlnzxwf')
 
    # Construct the email message
#    message = f'Thank you for voting for {candidate_name}!'
#    subject = 'Vote Confirmation'
#    msg = f'Subject: {subject}\n\n{message}'
 
    # Send the email
#    server.sendmail('asmaaloui112@example.com', to_email, msg)
 
    # Disconnect from the server
#    server.quit()
    
# Create a user
@app.route('/user', methods=['POST'])
def create_user():
    id = request.json['id']
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    governate = request.json['governate']
    electoral_circle = request.json['electoral_circle']
    role = request.json['role']

    hashed_password = pbkdf2_sha256.hash(password)

    new_user = User(id=id, username=username, password=hashed_password, email=email, first_name=first_name, last_name=last_name, governate=governate, electoral_circle=electoral_circle, voted=False, role=role)
    db.session.add(new_user)
    db.session.commit()
    return ({'message': 'User Added Succesfully'}), 200

# Get all users
@app.route('/user', methods=['GET'])
@jwt_required
def get_users():
    # Get the current user's ID
    current_user_id = get_jwt_identity()

    # Query the User model to get the current user
    current_user = User.query.filter_by(id=current_user_id).first()

    # Check if the current user is an admin
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 401

    # Get all users
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)

# Get a single user
@app.route('/user/<id>', methods=['GET'])
@jwt_required
def get_user(id):
    # Get the current user's ID
    current_user_id = get_jwt_identity()

    # Query the User model to get the current user
    current_user = User.query.filter_by(id=current_user_id).first()

    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 401

    user = User.query.get(id)
    return user_schema.jsonify(user)

# Update a user
@app.route('/user/<id>', methods=['PUT'])
@jwt_required
def update_user(id):
    # Get the current user's ID
    current_user_id = get_jwt_identity()

    # Query the User model to get the current user
    current_user = User.query.filter_by(id=current_user_id).first()
    if current_user.role != 'user':
        return jsonify({'message': 'Unauthorized'}), 401

    user = User.query.get(id)
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    first_name = request.json['first_name']
    last_name = request.json['last_name']
    governate = request.json['governate']
    electoral_circle = request.json['electoral_circle']
    role = request.json['role']
    hashed_password = pbkdf2_sha256.hash(password)
    user.username = username
    user.password = hashed_password
    user.email = email
    user.first_name = first_name
    user.last_name= last_name
    user.governate = governate
    user.electoral_circle = electoral_circle
    user.role = role
    db.session.commit()
    return user_schema.jsonify(user)

# Delete a user
@app.route('/user/<id>', methods=['DELETE'])
@jwt_required
def delete_user(id):
    # Get the current user's ID
    current_user_id = get_jwt_identity()

    # Query the User model to get the current user
    current_user = User.query.filter_by(id=current_user_id).first()
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 401

    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User Deleted Succesfully'}), 200

# Create a candidate
@app.route('/candidate', methods=['POST'])
@jwt_required
def create_candidate():
    # Get the current user's ID
    current_user_id = get_jwt_identity()

    # Query the User model to get the current user
    current_user = User.query.filter_by(id=current_user_id).first()
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 401

    name = request.json['name']
    governate = request.json['governate']
    electoral_circle = request.json['electoral_circle']

    new_candidate = Candidate(name=name, governate=governate, electoral_circle=electoral_circle)
    db.session.add(new_candidate)
    db.session.commit()
    return candidate_schema.jsonify(new_candidate)

# Get all candidates
@app.route('/candidate', methods=['GET'])
def get_candidates():
    all_candidates = Candidate.query.all()
    result = candidates_schema.dump(all_candidates)
    return jsonify(result)

# Get candidates by electoral circle
@app.route('/candidate/<electoral_circle>', methods=['GET'])
def get_candidate(electoral_circle):
    candidates = Candidate.query.filter_by(electoral_circle=electoral_circle).all()
    result = candidates_schema.dump(candidates)
    return jsonify(result)

# Update a candidate
@app.route('/candidate/<id>', methods=['PUT'])
@jwt_required
def update_candidate(id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    if current_user.role != 'admin':
        return jsonify({'message': 'Unauthorized'}), 401

    candidate = Candidate.query.get(id)
    name = request.json['name']
    governate = request.json['governate']
    electoral_circle = request.json['electoral_circle']

    candidate.name = name
    candidate.governate = governate
    candidate.electoral_circle = electoral_circle

    db.session.commit()
    return candidate_schema.jsonify(candidate)

# Delete a candidate
@app.route('/candidate/<candidate_id>', methods=['DELETE'])
@jwt_required
def delete_candidate(candidate_id):
    # Get the current user object from the database
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    if current_user.role != 'admin':
      return jsonify({'message': 'Unauthorized'}), 401

    candidate = Candidate.query.get(candidate_id)
    db.session.delete(candidate)
    db.session.commit()
    return jsonify({'message': 'Candidate Deleted Succesfully'}), 200

# Confirm identity and vote
@app.route('/vote', methods=['POST'])
@jwt_required
def vote():
    user_id = request.json['user_id']
    candidate_name = request.json['candidate_name']

    user = User.query.get(user_id)
    if user.voted:
        return jsonify({'message': 'You have already voted!'})

    candidate = Candidate.query.filter_by(name=candidate_name).first()
    if candidate is None:
        return jsonify({'message': 'Candidate not found!'})
    if candidate.governate != user.governate or candidate.electoral_circle != user.electoral_circle:
        return jsonify({'message': 'Invalid candidate for your governate and electoral circle!'})

    user.voted = True
    db.session.commit()

    # Send email confirmation
#    send_confirmation_email(user.email, candidate_name)

    return jsonify({'message': 'Vote successful!'})

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    user = User.query.filter_by(username=username).first()
    if user and  user.password:
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token})
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

# Logout endpoint
@app.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    jwt_id = get_jwt_identity()
    blacklist.add(jwt_id)
    return jsonify({'message': 'Successfully logged out'}), 200

# Check if the user is logged in
@app.route('/status', methods=['GET'])
@jwt_required
def status():
    return jsonify({'message': 'Logged in'}), 200

# Error handler for expired tokens
@jwt.expired_token_loader
def expired_token_callback(expired_token):
    token_type = expired_token['type']
    return jsonify({
        'message': 'The {} token has expired'.format(token_type),
        'error': 'token_expired'
    }), 401

# Error handler for invalid tokens
@jwt.invalid_token_loader
def invalid_token_callback(invalid_token):
    if isinstance(invalid_token, dict):
        token_type = invalid_token['type']
        return jsonify({
            'message': 'The {} token is invalid'.format(token_type),
            'error': 'invalid_token'
        }), 401
    else:
        return jsonify({
            'message': 'Invalid token',
            'error': 'invalid_token'
        }), 401

# Error handler for unauthorized requests
@jwt.unauthorized_loader
def unauthorizedcallback(error):
    return jsonify({
        'message': 'Unauthorized',
        'error': 'unauthorized'
    }), 401

# Error handler for blacklisted tokens
@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist

# Refresh token endpoint
@app.route('/refresh', methods=['POST'])
@jwt_required
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify({'access_token': new_token}), 200

# Run the app
if __name__ == '__main__':
    app.run(debug=True)




