from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, Response
import os
import requests
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import csv
from io import StringIO
from roboflow import Roboflow
import tempfile
import zipfile
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import secrets
from functools import wraps
import uuid
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))
app.permanent_session_lifetime = timedelta(hours=1)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
# Disable Flask caching - for development only
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True
# Set cookie settings
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Configure MongoDB
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb+srv://charankunda:saicharan12@logindatabasee.xjygbe3.mongodb.net/logindatabasee?retryWrites=true&w=majority&appName=logindatabasee")

# Initialize MongoDB
try:
    client = MongoClient(app.config["MONGO_URI"])
    db = client['aquaculture_db']  # Combined database for shrimp and fish analyses
    shrimp_collection = db['shrimp_inspections']
    fish_collection = db['fish_inspections']
    report_collection = db['reports']  # Collection for storing report metadata
    print("MongoDB connected successfully")
except Exception as e:
    print(f"MongoDB connection failed: {e}")

# Initialize OAuth
oauth = OAuth(app)

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Configure Facebook OAuth
facebook = oauth.register(
    name='facebook',
    client_id=os.environ.get("FACEBOOK_APP_ID"),
    client_secret=os.environ.get("FACEBOOK_APP_SECRET"),
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)

# Configure LinkedIn OAuth
linkedin = oauth.register(
    name='linkedin',
    client_id=os.environ.get("LINKEDIN_CLIENT_ID"),
    client_secret=os.environ.get("LINKEDIN_CLIENT_SECRET"),
    access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
    authorize_url='https://www.linkedin.com/oauth/v2/authorization',
    api_base_url='https://api.linkedin.com/v2/',
    client_kwargs={'scope': 'r_liteprofile r_emailaddress'},
)

# Roboflow setup for fish disease
rf = Roboflow(api_key="9tYzmTidplS3HH6lCb9a")
fish_project = rf.workspace("varun-nua2n").project("fish-disease-4hqd4-ijwl0")
fish_model = fish_project.version(1).model

# Disease suggestions
shrimp_disease_suggestions = {
    "Wssv": "Apply immunostimulants like beta-glucans. Maintain optimum pond salinity. Disinfect with chlorine-based products. Avoid sudden temperature drops.",
    "Blackgill": "Improve water quality. Increase aeration. Reduce organic load and remove sludge. Use probiotic treatments to restore microbial balance.",
    "Healthy": "No disease detected. Continue regular monitoring and maintain good pond management practices.",
    "Unknown": "Unable to determine disease. Please retake the image or consult an aquaculture specialist."
}

fish_disease_suggestions = {
    "Healthy": "Fish appears healthy. Continue regular monitoring and maintain good water quality.",
    "Unhealthy": "Signs of disease detected. Consider quarantining affected fish, improving water parameters, and consulting with a fish health specialist."
}

# Initialize database for users and farms
def init_db():
    try:
        if 'users' not in db.list_collection_names():
            db.create_collection('users')
            print("Created users collection")
        if 'farms' not in db.list_collection_names():
            db.create_collection('farms')
            print("Created farms collection")
        db.users.create_index("username", unique=True, background=True)
        db.users.create_index("email", unique=True, background=True)
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Create or get user
def create_or_get_user(email, username, provider='local', provider_id=None):
    try:
        user = db.users.find_one({'email': email})
        if user:
            db.users.update_one({'_id': user['_id']}, {'$set': {'last_login_provider': provider}})
            return user
        else:
            new_user = {
                'username': username,
                'email': email,
                'password': None,
                'provider': provider,
                'provider_id': provider_id,
                'last_login_provider': provider
            }
            result = db.users.insert_one(new_user)
            new_user['_id'] = result.inserted_id
            return new_user
    except Exception as e:
        print(f"Error creating/getting user: {e}")
        return None

# Configure Upload Folder
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Make sure templates directory exists
templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
os.makedirs(templates_dir, exist_ok=True)

# AUTH ROUTES

# Add this new route for the landing page
@app.route('/')
def landing_page():
    """Render the landing page as the initial route"""
    return render_template('landing.html')

# Change your existing index route to this:
@app.route('/login')
def index():
    """Render the login/signup page"""
    # Initialize the database
    init_db()
    
    # Explicitly check for valid user session
    if 'user' in session and session['user'] is not None and 'id' in session['user']:
        try:
            # Verify the user exists in the database
            user_id = session['user']['id']
            user = db.users.find_one({"_id": ObjectId(user_id)})
            if user:
                return redirect(url_for('dashboard'))
            else:
                # User doesn't exist, clear session
                session.clear()
        except:
            # Error retrieving user, clear session
            session.clear()
    
    # Default behavior - show login page
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            return render_template('index.html', error="Please enter both username and password")
        user = db.users.find_one({'username': username})
        if user and user.get('password') and check_password_hash(user['password'], password):
            # Store user info in session
            session.clear()  # Clear any existing session
            session['user'] = {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'provider': user.get('provider', 'local')
            }
            # Force the session to be saved
            session.modified = True
            # Make the session permanent
            session.permanent = True
            # Redirect with absolute URL
            return redirect(url_for('dashboard'))
        else:
            return render_template('index.html', error="Invalid username or password")
    except Exception as e:
        print(f"Login error: {str(e)}")
        return render_template('index.html', error="An error occurred during login. Please try again.")

@app.route('/signup', methods=['POST'])
def signup():
    try:
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not email or not username or not password:
            return render_template('index.html', error="Please fill in all fields")
        if len(password) < 6:
            return render_template('index.html', error="Password must be at least 6 characters long")
        if len(username) < 3:
            return render_template('index.html', error="Username must be at least 3 characters long")
        existing_user = db.users.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing_user:
            if existing_user['username'] == username:
                return render_template('index.html', error="Username already exists")
            else:
                return render_template('index.html', error="Email already exists")
        hashed_password = generate_password_hash(password)
        result = db.users.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password,
            'provider': 'local'
        })
        if result.inserted_id:
            return render_template('index.html', success="Account created successfully! Please login.")
        else:
            return render_template('index.html', error="Failed to create account. Please try again.")
    except Exception as e:
        print(f"Signup error: {e}")
        return render_template('index.html', error="An error occurred during registration. Please try again.")

@app.route('/auth/<provider>')
def oauth_login(provider):
    try:
        redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
        if provider == 'google':
            return google.authorize_redirect(redirect_uri)
        elif provider == 'facebook':
            return facebook.authorize_redirect(redirect_uri)
        elif provider == 'linkedin':
            return linkedin.authorize_redirect(redirect_uri)
        else:
            flash(f"OAuth provider '{provider}' is not supported", 'error')
            return redirect(url_for('index'))
    except Exception as e:
        print(f"OAuth login error for {provider}: {e}")
        flash(f"Error initiating {provider} login", 'error')
        return redirect(url_for('index'))

@app.route('/auth/<provider>/callback')
def oauth_callback(provider):
    try:
        user = None
        if provider == 'google':
            token = google.authorize_access_token()
            user_info = token.get('userinfo')
            if user_info:
                email = user_info.get('email')
                name = user_info.get('name', email.split('@')[0])
                provider_id = user_info.get('sub')
                user = create_or_get_user(email, name, 'google', provider_id)
        elif provider == 'facebook':
            token = facebook.authorize_access_token()
            resp = facebook.get('me?fields=id,name,email', token=token)
            user_info = resp.json()
            email = user_info.get('email')
            name = user_info.get('name', email.split('@')[0] if email else 'Facebook User')
            provider_id = user_info.get('id')
            if email:
                user = create_or_get_user(email, name, 'facebook', provider_id)
        elif provider == 'linkedin':
            token = linkedin.authorize_access_token()
            headers = {'Authorization': f'Bearer {token["access_token"]}'}
            profile_resp = requests.get('https://api.linkedin.com/v2/me', headers=headers)
            email_resp = requests.get(
                'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))',
                headers=headers)
            if profile_resp.ok and email_resp.ok:
                profile_data = profile_resp.json()
                email_data = email_resp.json()
                email = email_data['elements'][0]['handle~']['emailAddress']
                name = f"{profile_data.get('localizedFirstName', '')} {profile_data.get('localizedLastName', '')}".strip()
                provider_id = profile_data.get('id')
                user = create_or_get_user(email, name or 'LinkedIn User', 'linkedin', provider_id)
        if user:
            session['user'] = {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email'],
                'provider': provider
            }
            session.permanent = True
            session.modified = True
            flash(f'Welcome, {user["username"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(f'{provider.title()} login failed', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        print(f"OAuth callback error for {provider}: {e}")
        flash(f'Error during {provider} login: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    username = session.get('user', {}).get('username', 'User')
    session.clear()
    flash(f'Goodbye, {username}! You have been logged out successfully.', 'success')
    return redirect(url_for('index'))

# FARM MANAGEMENT API ROUTES
@app.route('/api/farms', methods=['GET'])
@login_required
def get_farms():
    """Get all farms for the current user"""
    try:
        # Get current user's ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        # Query farms for this user
        farms = list(db.farms.find({"user_id": user_id}).sort("farm_name", 1))
        
        # Convert ObjectId to string for JSON serialization
        for farm in farms:
            farm['_id'] = str(farm['_id'])
        
        return jsonify({"success": True, "farms": farms})
    except Exception as e:
        print(f"Error fetching farms: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/farms/add', methods=['POST'])
@login_required
def add_farm():
    """Add a new farm"""
    try:
        # Get current user's ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        # Get data from request
        data = request.json
        
        # Basic validation
        if not data.get('farm_name') or not data.get('farm_id') or not data.get('farm_location'):
            return jsonify({"success": False, "error": "Missing required fields"}), 400
        
        # Check if farm ID already exists for this user
        existing_farm = db.farms.find_one({
            "user_id": user_id,
            "farm_id": data.get('farm_id')
        })
        
        if existing_farm:
            return jsonify({"success": False, "error": "Farm ID already exists"}), 400
        
        # Create farm object
        farm = {
            "user_id": user_id,
            "farm_name": data.get('farm_name'),
            "farm_id": data.get('farm_id'),
            "farm_location": data.get('farm_location'),
            "farm_size": data.get('farm_size'),
            "farm_type": data.get('farm_type'),
            "farm_notes": data.get('farm_notes'),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        # Insert into database
        result = db.farms.insert_one(farm)
        
        return jsonify({
            "success": True,
            "farm_id": str(result.inserted_id),
            "message": "Farm added successfully"
        })
    
    except Exception as e:
        print(f"Error adding farm: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/farms/<farm_id>', methods=['GET'])
@login_required
def get_farm(farm_id):
    """Get a specific farm by ID"""
    try:
        # Get current user's ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        # Find the farm
        farm = db.farms.find_one({
            "_id": ObjectId(farm_id),
            "user_id": user_id
        })
        
        if not farm:
            return jsonify({"success": False, "error": "Farm not found"}), 404
        
        # Convert ObjectId to string for JSON serialization
        farm['_id'] = str(farm['_id'])
        
        return jsonify({"success": True, "farm": farm})
    
    except Exception as e:
        print(f"Error fetching farm: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/farms/update', methods=['PUT'])
@login_required
def update_farm():
    """Update an existing farm"""
    try:
        # Get current user's ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        # Get data from request
        data = request.json
        
        # Basic validation
        if not data.get('farm_name') or not data.get('farm_id') or not data.get('farm_location'):
            return jsonify({"success": False, "error": "Missing required fields"}), 400
        
        farm_id = data.get('farm_edit_id')
        
        # Check if farm exists and belongs to this user
        farm = db.farms.find_one({
            "_id": ObjectId(farm_id),
            "user_id": user_id
        })
        
        if not farm:
            return jsonify({"success": False, "error": "Farm not found"}), 404
        
        # Check if updating to an existing farm ID (that's not this farm's current ID)
        if data.get('farm_id') != farm['farm_id']:
            existing_farm = db.farms.find_one({
                "user_id": user_id,
                "farm_id": data.get('farm_id'),
                "_id": {"$ne": ObjectId(farm_id)}
            })
            
            if existing_farm:
                return jsonify({"success": False, "error": "Farm ID already exists"}), 400
        
        # Update farm data
        update_data = {
            "farm_name": data.get('farm_name'),
            "farm_id": data.get('farm_id'),
            "farm_location": data.get('farm_location'),
            "farm_size": data.get('farm_size'),
            "farm_type": data.get('farm_type'),
            "farm_notes": data.get('farm_notes'),
            "updated_at": datetime.utcnow()
        }
        
        # Update in database
        db.farms.update_one(
            {"_id": ObjectId(farm_id)},
            {"$set": update_data}
        )
        
        return jsonify({
            "success": True,
            "message": "Farm updated successfully"
        })
    
    except Exception as e:
        print(f"Error updating farm: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/farms/<farm_id>', methods=['DELETE'])
@login_required
def delete_farm(farm_id):
    """Delete a farm"""
    try:
        # Get current user's ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        # Check if farm exists and belongs to this user
        farm = db.farms.find_one({
            "_id": ObjectId(farm_id),
            "user_id": user_id
        })
        
        if not farm:
            return jsonify({"success": False, "error": "Farm not found"}), 404
        
        # Delete the farm
        db.farms.delete_one({"_id": ObjectId(farm_id)})
        
        return jsonify({
            "success": True,
            "message": "Farm deleted successfully"
        })
    
    except Exception as e:
        print(f"Error deleting farm: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

# DASHBOARD ROUTES
@app.route('/dashboard')
@login_required
def dashboard():
    """Render the dashboard page"""
    try:
        # Get user information from session
        user = session.get('user')
        if not user:
            # If user is not in session, redirect to login page
            flash('Please log in to access the dashboard.', 'error')
            return redirect(url_for('index'))
            
        # Return the dashboard template with user info
        return render_template('dashboard.html', user=user)
    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash('An error occurred while loading the dashboard.', 'error')
        return redirect(url_for('index'))

# PREDICTION ROUTES
@app.route('/predict/batch', methods=['POST'])
@login_required
def predict_batch():
    """Handle batch image analysis submission"""
    try:
        # Get form data
        specimen_type = request.form.get('specimen_type', 'fish')
        farm_id = request.form.get('farm_id', '')
        farm_name = request.form.get('farm_name', '')
        farm_location = request.form.get('farm_location', '')
        
        # Check if farm information is provided
        if not farm_id or not farm_name:
            return render_template('dashboard.html', error="Please select a farm first")
        
        # Validate file uploads
        if 'images[]' not in request.files:
            return render_template('dashboard.html', error="No images uploaded")
        
        files = request.files.getlist('images[]')
        if len(files) == 0 or files[0].filename == '':
            return render_template('dashboard.html', error="No files selected")

        # Create a batch ID to group these analyses
        batch_id = str(uuid.uuid4())
        
        # Get user ID
        user_id = session.get('user', {}).get('id')
        
        # Store metadata
        metadata = {
            "farm_id": farm_id,
            "farm_name": farm_name,
            "farm_location": farm_location,
            "batch_id": batch_id,
            "user_id": user_id
        }
        
        # Process each image and collect results
        results = []
        
        for file in files:
            # Secure filename and save the file
            filename = secure_filename(file.filename)
            timestamp = str(int(time.time()))
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                if specimen_type == 'shrimp':
                    # Process shrimp image
                    url = "https://detect.roboflow.com/shrimp-disease-classification-qin1p-tlxpc/1"
                    params = {"api_key": "9tYzmTidplS3HH6lCb9a"}
                    with open(filepath, "rb") as f:
                        response = requests.post(url, files={"file": f}, params=params)
                    
                    result = response.json()
                    if 'predictions' in result and len(result['predictions']) > 0:
                        prediction = result['predictions'][0]
                        health_status = prediction['class']
                        confidence = round(prediction['confidence'], 2)
                    else:
                        health_status = "Unknown"
                        confidence = 0.0
                    
                    # Save to MongoDB
                    record = {
                        "filepath": filepath,
                        "filename": filename,
                        "health_status": health_status,
                        "confidence": confidence,
                        "type": "shrimp",
                        "timestamp": datetime.utcnow(),
                        "metadata": metadata,
                        "batch_id": batch_id,
                        "farm_id": farm_id,
                        "farm_name": farm_name,
                        "farm_location": farm_location,
                        "user_id": user_id
                    }
                    result_id = shrimp_collection.insert_one(record).inserted_id
                    
                else:  # Fish analysis
                    # Process fish image
                    prediction_json = fish_model.predict(filepath).json()
                    predicted_classes = prediction_json['predictions'][0]['predicted_classes'] if 'predictions' in prediction_json and len(prediction_json['predictions']) > 0 else []
                    is_healthy = "Healthy" in predicted_classes
                    health_status = "Healthy" if is_healthy else "Unhealthy"
                    
                    # Save to MongoDB
                    record = {
                        "filename": filename,
                        "filepath": filepath,
                        "health_status": health_status,
                        "is_healthy": is_healthy,
                        "type": "fish",
                        "timestamp": datetime.utcnow(),
                        "metadata": metadata,
                        "batch_id": batch_id,
                        "farm_id": farm_id,
                        "farm_name": farm_name,
                        "farm_location": farm_location,
                        "user_id": user_id
                    }
                    result_id = fish_collection.insert_one(record).inserted_id
                
                # Add to results list
                results.append({
                    "id": str(result_id),
                    "filename": filename,
                    "health_status": health_status,
                    "confidence": confidence if specimen_type == 'shrimp' else "N/A"
                })
                
            except Exception as e:
                print(f"Error processing {filename}: {str(e)}")
                # Continue with other images even if one fails
                results.append({
                    "filename": filename,
                    "error": str(e)
                })
        
        # Create a summary record of the batch processing
        batch_summary = {
            "batch_id": batch_id,
            "type": specimen_type,
            "farm_id": farm_id,
            "farm_name": farm_name,
            "farm_location": farm_location,
            "user_id": user_id,
            "total_images": len(files),
            "processed_images": len(results),
            "timestamp": datetime.utcnow(),
            "results": results
        }
        
        # Store the batch summary in a separate collection
        if not hasattr(db, 'batch_analyses'):
            db.create_collection('batch_analyses')
        
        batch_collection = db['batch_analyses']
        batch_id = batch_collection.insert_one(batch_summary).inserted_id
        
        # Redirect to a batch results page
        return redirect(url_for('batch_results', batch_id=batch_id))
    
    except Exception as e:
        print(f"Error in predict_batch: {str(e)}")
        return render_template('dashboard.html', error=f"Batch processing error: {str(e)}")

# RESULT ROUTES
@app.route('/result/<analysis_type>/<record_id>')
@login_required
def result(analysis_type, record_id):
    try:
        # Get the record from the appropriate collection
        if analysis_type == 'shrimp':
            record = shrimp_collection.find_one({"_id": ObjectId(record_id)})
            suggestion = shrimp_disease_suggestions.get(record["health_status"], "No specific suggestion available.")
        else:  # fish
            record = fish_collection.find_one({"_id": ObjectId(record_id)})
            suggestion = fish_disease_suggestions.get(record["health_status"], "No specific suggestion available.")
        
        if not record:
            return "Result not found", 404

        filename = os.path.basename(record["filepath"])
        
        # Get farm information
        farm_id = record.get('farm_id', '')
        farm_name = record.get('farm_name', '')
        farm_location = record.get('farm_location', '')
        
        # If there's no direct farm info, check metadata
        if not farm_id and 'metadata' in record:
            farm_id = record['metadata'].get('farm_id', '')
            farm_name = record['metadata'].get('farm_name', '')
            farm_location = record['metadata'].get('farm_location', '')
        
        # Check if this record is part of a batch
        batch_info = {}
        batch_id = record.get('batch_id', '')
        if not batch_id and 'metadata' in record:
            batch_id = record['metadata'].get('batch_id', '')
            
        if batch_id:
            # Get batch collection
            batch_collection = db['batch_analyses']
            batch = batch_collection.find_one({"batch_id": batch_id})
            
            if batch:
                # Find all records in this batch
                if analysis_type == 'shrimp':
                    batch_records = list(shrimp_collection.find({"$or": [{"batch_id": batch_id}, {"metadata.batch_id": batch_id}]}).sort('timestamp', 1))
                else:
                    batch_records = list(fish_collection.find({"$or": [{"batch_id": batch_id}, {"metadata.batch_id": batch_id}]}).sort('timestamp', 1))
                
                # Find position of current record in batch
                # Find position of current record in batch
                record_ids = [str(r['_id']) for r in batch_records]
                try:
                    current_index = record_ids.index(record_id)
                    batch_position = current_index + 1
                    batch_total = len(record_ids)
                    
                    # Get previous and next record IDs for navigation
                    prev_id = record_ids[current_index - 1] if current_index > 0 else None
                    next_id = record_ids[current_index + 1] if current_index < len(record_ids) - 1 else None
                    
                    batch_info = {
                        'batch_id': str(batch['_id']),
                        'batch_id_str': batch_id,
                        'batch_position': batch_position,
                        'batch_total': batch_total,
                        'prev_id': prev_id,
                        'next_id': next_id
                    }
                except ValueError:
                    # Record not found in batch (shouldn't happen, but just in case)
                    pass
        
        # Create a context dictionary with all the parameters
        context = {
            'record_id': record_id,
            'image_url': url_for('static', filename='uploads/' + filename),
            'health_status': record["health_status"],
            'confidence': record.get("confidence", 0.0),
            'suggestion': suggestion,
            'analysis_type': analysis_type,
            'timestamp': record["timestamp"],
            'farm_id': farm_id,
            'farm_name': farm_name,
            'farm_location': farm_location,
            'user': session.get('user')  # Add user info for header
        }
        
        # Update context with batch_info
        context.update(batch_info)
        
        return render_template('result.html', **context)
    
    except Exception as e:
        print(f"Error in result route: {str(e)}")
        return f"Error retrieving result: {str(e)}", 500

@app.route('/batch_results/<batch_id>')
@login_required
def batch_results(batch_id):
    """Display results of a batch analysis"""
    try:
        # Get the batch summary from MongoDB
        batch_collection = db['batch_analyses']
        batch = batch_collection.find_one({"_id": ObjectId(batch_id)})
        
        if not batch:
            return "Batch not found", 404
        
        # Get the specimen type
        specimen_type = batch.get('type', 'unknown')
        batch_id_str = batch.get('batch_id', '')
        farm_id = batch.get('farm_id', '')
        farm_name = batch.get('farm_name', '')
        farm_location = batch.get('farm_location', '')
        
        # Get all individual analyses in this batch
        if specimen_type == 'shrimp':
            batch_records = list(shrimp_collection.find({"$or": [{"batch_id": batch_id_str}, {"metadata.batch_id": batch_id_str}]}).sort('timestamp', 1))
        else:  # fish
            batch_records = list(fish_collection.find({"$or": [{"batch_id": batch_id_str}, {"metadata.batch_id": batch_id_str}]}).sort('timestamp', 1))
        
        # Calculate summary statistics
        total_count = len(batch_records)
        healthy_count = sum(1 for record in batch_records if record.get('health_status') == 'Healthy')
        unhealthy_count = total_count - healthy_count
        
        if total_count == 0:
            return "No records found for this batch", 404
        
        # Format records for display
        formatted_records = []
        for record in batch_records:
            formatted_records.append({
                'id': str(record['_id']),
                'filename': os.path.basename(record['filepath']),
                'health_status': record['health_status'],
                'confidence': record.get('confidence', 'N/A'),
                'timestamp': record['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                'image_url': url_for('static', filename='uploads/' + os.path.basename(record['filepath']))
            })
        
        # Calculate percentage healthy for summary display
        percentage_healthy = (healthy_count / total_count * 100) if total_count > 0 else 0
        
        # Create a context for the template
        context = {
            'batch_id': batch_id,
            'batch_id_str': batch_id_str,
            'farm_id': farm_id,
            'farm_name': farm_name,
            'farm_location': farm_location,
            'specimen_type': specimen_type,
            'records': formatted_records,
            'batch_summary': {
                'total_count': total_count,
                'healthy_count': healthy_count,
                'unhealthy_count': unhealthy_count,
                'percentage_healthy': percentage_healthy
            },
            'is_batch_view': True,  # Indicates this is a batch view, not a single result
            'user': session.get('user')  # Add user info for header
        }
        
        # Create a custom template for displaying batch results
        return render_template('batch_results.html', **context)
    
    except Exception as e:
        print(f"Error in batch_results: {str(e)}")
        return f"Error retrieving batch results: {str(e)}", 500

# ERROR HANDLERS
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error="Internal server error. Please try again later."), 500

@app.route('/health')
def health_check():
    try:
        db.users.find_one()
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@app.route('/generate_batch_report/<batch_id>')
@login_required
def generate_batch_report(batch_id):
    """Generate a comprehensive report for all analyses in a batch"""
    try:
        # Get the batch summary
        batch_collection = db['batch_analyses']
        batch = batch_collection.find_one({"_id": ObjectId(batch_id)})
        
        if not batch:
            return "Batch not found", 404
        
        specimen_type = batch.get('type', 'unknown')
        batch_id_str = batch.get('batch_id', '')
        
        # Get all records in this batch
        if specimen_type == 'shrimp':
            records = list(shrimp_collection.find({"$or": [{"batch_id": batch_id_str}, {"metadata.batch_id": batch_id_str}]}))
        else:  # fish
            records = list(fish_collection.find({"$or": [{"batch_id": batch_id_str}, {"metadata.batch_id": batch_id_str}]}))
        
        # Calculate statistics
        total_count = len(records)
        healthy_count = sum(1 for record in records if record.get('health_status') == 'Healthy')
        unhealthy_count = total_count - healthy_count
        # For shrimp, count specific diseases
        disease_counts = {}
        if specimen_type == 'shrimp':
            for record in records:
                status = record.get('health_status', 'Unknown')
                if status != 'Healthy':
                    disease_counts[status] = disease_counts.get(status, 0) + 1
        
        # Create the report content
        now = datetime.utcnow()
        farm_id = batch.get('farm_id', 'N/A')
        farm_name = batch.get('farm_name', 'N/A')
        farm_location = batch.get('farm_location', 'N/A')
        
        report_content = f"""
AQUACULTURE BATCH ANALYSIS REPORT
================================
Date: {now.strftime('%Y-%m-%d')}
Time: {now.strftime('%H:%M:%S')}
Batch ID: {batch_id_str}
Farm ID: {farm_id}
Farm Name: {farm_name}
Farm Location: {farm_location}
Specimen Type: {specimen_type.capitalize()}

SUMMARY
-------
Total Images Analyzed: {total_count}
Healthy: {healthy_count} ({healthy_count/total_count*100 if total_count > 0 else 0:.1f}%)
Unhealthy: {unhealthy_count} ({unhealthy_count/total_count*100 if total_count > 0 else 0:.1f}%)
"""
        
        # Add disease breakdown for shrimp
        if specimen_type == 'shrimp' and disease_counts:
            report_content += "\nDISEASE BREAKDOWN\n-----------------\n"
            for disease, count in disease_counts.items():
                report_content += f"{disease}: {count} ({count/total_count*100 if total_count > 0 else 0:.1f}%)\n"
        
        # Add recommendations based on results
        report_content += "\nRECOMMENDATIONS\n---------------\n"
        
        if specimen_type == 'shrimp':
            # Shrimp-specific recommendations
            if 'Wssv' in disease_counts and disease_counts['Wssv'] > 0:
                report_content += "WSSV Detected:\n"
                report_content += "- Apply immunostimulants like beta-glucans\n"
                report_content += "- Maintain optimum pond salinity\n"
                report_content += "- Disinfect with chlorine-based products\n"
                report_content += "- Avoid sudden temperature drops\n\n"
            
            if 'Blackgill' in disease_counts and disease_counts['Blackgill'] > 0:
                report_content += "Blackgill Detected:\n"
                report_content += "- Improve water quality\n"
                report_content += "- Increase aeration\n"
                report_content += "- Reduce organic load and remove sludge\n"
                report_content += "- Use probiotic treatments to restore microbial balance\n\n"
        
        else:  # Fish recommendations
            if unhealthy_count > 0:
                report_content += "Unhealthy Fish Detected:\n"
                report_content += "- Consider quarantining affected fish\n"
                report_content += "- Improve water parameters\n"
                report_content += "- Consult with a fish health specialist\n"
                report_content += "- Monitor feed quality and feeding protocols\n\n"
        
        # Add general recommendations
        report_content += "General Recommendations:\n"
        report_content += "- Continue regular health monitoring\n"
        report_content += "- Maintain optimal water quality parameters\n"
        report_content += "- Implement biosecurity measures to prevent disease spread\n"
        
        # Add detailed results
        report_content += "\nDETAILED RESULTS\n---------------\n"
        for i, record in enumerate(records, 1):
            report_content += f"""
Image {i}: {os.path.basename(record['filepath'])}
  Health Status: {record.get('health_status', 'Unknown')}
  {"Confidence: " + f"{record.get('confidence', 0) * 100:.1f}%" if 'confidence' in record else ""}
  Analysis Time: {record['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        # Generate the report file
        report_filename = f"batch_report_{batch_id_str}_{now.strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
        
        # Write the report to a file
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        # Log the report in the database
        report_id = report_collection.insert_one({
            'name': f"Batch Analysis Report - {farm_name}",
            'type': 'batch',
            'format': 'txt',
            'filepath': report_path,
            'timestamp': datetime.utcnow(),
            'batch_id': batch_id_str,
            'farm_id': farm_id,
            'farm_name': farm_name,
            'farm_location': farm_location
        }).inserted_id
        
        # Send the file for download
        return send_from_directory(
            directory=app.config['UPLOAD_FOLDER'], 
            path=report_filename,
            as_attachment=True
        )
    
    except Exception as e:
        print(f"Error generating batch report: {str(e)}")
        return f"Error generating batch report: {str(e)}", 500

# API Endpoints
@app.route('/api/history/shrimp')
@login_required
def api_shrimp_history():
    """API endpoint to get shrimp analysis records"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get query parameters for filtering
        date_filter = request.args.get('date', 'all')
        status_filter = request.args.get('status', 'all')
        search_term = request.args.get('search', '')
        farm_id = request.args.get('farm_id', 'all')
        
        # Build the query filter
        query = {"user_id": user_id}
        
        # Add date filter
        if date_filter != 'all':
            end_date = datetime.utcnow()
            if date_filter == 'today':
                start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
            elif date_filter == 'week':
                start_date = end_date - timedelta(days=7)
            elif date_filter == 'month':
                start_date = end_date - timedelta(days=30)
            elif date_filter == 'quarter':
                start_date = end_date - timedelta(days=90)
            else:
                start_date = datetime(2000, 1, 1)  # Default to a very old date
                
            query['timestamp'] = {'$gte': start_date, '$lte': end_date}
        
        # Add status filter
        if status_filter != 'all':
            if status_filter == 'healthy':
                query['health_status'] = 'Healthy'
            elif status_filter == 'unhealthy':
                query['health_status'] = {'$ne': 'Healthy'}
            else:
                # For specific diseases like 'wssv' or 'blackgill'
                query['health_status'] = status_filter.capitalize()
        
        # Add farm filter
        if farm_id != 'all':
            query['$or'] = [
                {'farm_id': farm_id},
                {'metadata.farm_id': farm_id}
            ]
        
        # Add search filter (if provided)
        if search_term:
            # Search in multiple fields
            search_conditions = [
                {'filename': {'$regex': search_term, '$options': 'i'}},
                {'health_status': {'$regex': search_term, '$options': 'i'}},
                {'farm_name': {'$regex': search_term, '$options': 'i'}},
                {'metadata.farm_name': {'$regex': search_term, '$options': 'i'}}
            ]
            
            # Combine search with existing query
            if '$or' in query:
                # If there's already an $or condition (from farm filter), use $and to combine
                query = {'$and': [{'$or': query['$or']}, {'$or': search_conditions}]}
            else:
                query['$or'] = search_conditions
        
        # Get records from MongoDB
        shrimp_records = list(shrimp_collection.find(query).sort('timestamp', -1))
        
        # Format the records for JSON response
        formatted_records = []
        for record in shrimp_records:
            # Get farm info from record or metadata
            farm_name = record.get('farm_name', '')
            if not farm_name and 'metadata' in record:
                farm_name = record['metadata'].get('farm_name', '')
                
            formatted_records.append({
                'id': str(record['_id']),
                'filename': os.path.basename(record['filepath']),
                'health_status': record['health_status'],
                'timestamp': record['timestamp'].isoformat(),
                'confidence': record.get('confidence', 0),
                'type': 'shrimp',
                'farm_name': farm_name,
                'farm_id': record.get('farm_id', '') or record.get('metadata', {}).get('farm_id', '')
            })
        
        return jsonify(formatted_records)
        
    except Exception as e:
        print(f"Error in api_shrimp_history: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/history/fish')
@login_required
def api_fish_history():
    """API endpoint to get fish analysis records"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get query parameters for filtering
        date_filter = request.args.get('date', 'all')
        status_filter = request.args.get('status', 'all')
        search_term = request.args.get('search', '')
        farm_id = request.args.get('farm_id', 'all')
        
        # Build the query filter
        query = {"user_id": user_id}
        
        # Add date filter
        if date_filter != 'all':
            end_date = datetime.utcnow()
            if date_filter == 'today':
                start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
            elif date_filter == 'week':
                start_date = end_date - timedelta(days=7)
            elif date_filter == 'month':
                start_date = end_date - timedelta(days=30)
            elif date_filter == 'quarter':
                start_date = end_date - timedelta(days=90)
            else:
                start_date = datetime(2000, 1, 1)  # Default to a very old date
                
            query['timestamp'] = {'$gte': start_date, '$lte': end_date}
        
        # Add status filter
        if status_filter != 'all':
            if status_filter == 'healthy':
                query['health_status'] = 'Healthy'
            elif status_filter == 'unhealthy':
                query['health_status'] = {'$ne': 'Healthy'}
            else:
                # For specific diseases
                query['health_status'] = status_filter.capitalize()
        
        # Add farm filter
        if farm_id != 'all':
            query['$or'] = [
                {'farm_id': farm_id},
                {'metadata.farm_id': farm_id}
            ]
        
        # Add search filter (if provided)
        if search_term:
            # Search in multiple fields
            search_conditions = [
                {'filename': {'$regex': search_term, '$options': 'i'}},
                {'health_status': {'$regex': search_term, '$options': 'i'}},
                {'farm_name': {'$regex': search_term, '$options': 'i'}},
                {'metadata.farm_name': {'$regex': search_term, '$options': 'i'}}
            ]
            
            # Combine search with existing query
            if '$or' in query:
                # If there's already an $or condition (from farm filter), use $and to combine
                query = {'$and': [{'$or': query['$or']}, {'$or': search_conditions}]}
            else:
                query['$or'] = search_conditions
        
        # Get records from MongoDB
        fish_records = list(fish_collection.find(query).sort('timestamp', -1))
        
        # Format the records for JSON response
        formatted_records = []
        for record in fish_records:
            # Get farm info from record or metadata
            farm_name = record.get('farm_name', '')
            if not farm_name and 'metadata' in record:
                farm_name = record['metadata'].get('farm_name', '')
                
            formatted_records.append({
                'id': str(record['_id']),
                'filename': os.path.basename(record['filepath']),
                'health_status': record['health_status'],
                'timestamp': record['timestamp'].isoformat(),
                'is_healthy': record.get('is_healthy', False),
                'type': 'fish',
                'farm_name': farm_name,
                'farm_id': record.get('farm_id', '') or record.get('metadata', {}).get('farm_id', '')
            })
        
        return jsonify(formatted_records)
        
    except Exception as e:
        print(f"Error in api_fish_history: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/statistics/dashboard')
@login_required
def api_dashboard_statistics():
    """API endpoint to get statistics for the dashboard"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get query parameters
        date_filter = request.args.get('date', 'all')
        farm_id = request.args.get('farm_id', 'all')
        
        # Build base query
        base_query = {"user_id": user_id}
        
        # Add farm filter
        if farm_id != 'all':
            base_query['$or'] = [
                {'farm_id': farm_id},
                {'metadata.farm_id': farm_id}
            ]
        
        # Build date filter
        if date_filter != 'all':
            end_date = datetime.utcnow()
            if date_filter == 'today':
                start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
            elif date_filter == 'week':
                start_date = end_date - timedelta(days=7)
            elif date_filter == 'month':
                start_date = end_date - timedelta(days=30)
            elif date_filter == 'quarter':
                start_date = end_date - timedelta(days=90)
            else:
                start_date = end_date - timedelta(days=365)  # Default to a year
                
            date_query = {'timestamp': {'$gte': start_date, '$lte': end_date}}
            # Merge date query with base query
            if '$or' in base_query:
                date_base_query = base_query.copy()
                date_base_query.update(date_query)
            else:
                date_base_query = {**base_query, **date_query}
        else:
            date_base_query = base_query
        
        # Get counts
        total_shrimp = shrimp_collection.count_documents(date_base_query)
        total_fish = fish_collection.count_documents(date_base_query)
        
        # Create queries for healthy counts
        healthy_query = {**date_base_query, "health_status": "Healthy"}
        healthy_shrimp = shrimp_collection.count_documents(healthy_query)
        healthy_fish = fish_collection.count_documents(healthy_query)
        
        # Get disease counts for shrimp
        wssv_query = {**date_base_query, "health_status": "Wssv"}
        blackgill_query = {**date_base_query, "health_status": "Blackgill"}
        wssv_count = shrimp_collection.count_documents(wssv_query)
        blackgill_count = shrimp_collection.count_documents(blackgill_query)
        
        # Get stats
        total_count = total_shrimp + total_fish
        healthy_count = healthy_shrimp + healthy_fish
        unhealthy_count = total_count - healthy_count
        
        # Calculate percentages
        healthy_percent = round((healthy_count / total_count * 100) if total_count > 0 else 0, 1)
        unhealthy_percent = round((unhealthy_count / total_count * 100) if total_count > 0 else 0, 1)
        
        # Get farms count
        farms_count = db.farms.count_documents({"user_id": user_id})
        
        return jsonify({
            'counts': {
                'total': total_count,
                'healthy': healthy_count,
                'unhealthy': unhealthy_count,
                'shrimp': total_shrimp,
                'fish': total_fish,
                'wssv': wssv_count,
                'blackgill': blackgill_count,
                'farms': farms_count
            },
            'percentages': {
                'healthy': healthy_percent,
                'unhealthy': unhealthy_percent
            }
        })
        
    except Exception as e:
        print(f"Error in api_dashboard_statistics: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/dashboard-data')
@login_required
def dashboard_data():
    """API endpoint to provide dashboard statistics and recent data"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
        
        # Get farm ID from query parameters (if provided)
        farm_id = request.args.get('farm_id', 'all')
        
        # Build base query for this user
        base_query = {"user_id": user_id}
        
        # Add farm filter if provided
        if farm_id != 'all':
            farm_query = {'$or': [
                {'farm_id': farm_id},
                {'metadata.farm_id': farm_id}
            ]}
            
            # Combine with base query
            query = {**base_query, **farm_query}
        else:
            query = base_query
            
        # Get counts from MongoDB for this user's data with optional farm filter
        total_shrimp = shrimp_collection.count_documents(query)
        total_fish = fish_collection.count_documents(query)
        
        healthy_shrimp = shrimp_collection.count_documents({**query, "health_status": "Healthy"})
        healthy_fish = fish_collection.count_documents({**query, "health_status": "Healthy"})
        
        # Calculate totals
        total_count = total_shrimp + total_fish
        healthy_count = healthy_shrimp + healthy_fish
        
        # Calculate unhealthy counts (assuming any non-healthy status is unhealthy)
        unhealthy_shrimp = shrimp_collection.count_documents({**query, "health_status": {"$ne": "Healthy"}})
        unhealthy_fish = fish_collection.count_documents({**query, "health_status": {"$ne": "Healthy"}})
        unhealthy_count = unhealthy_shrimp + unhealthy_fish
        
        # Calculate unknown counts (any that are neither healthy nor unhealthy)
        unknown_shrimp = shrimp_collection.count_documents({**query, "health_status": "Unknown"})
        unknown_fish = fish_collection.count_documents({**query, "health_status": "Unknown"})
        unknown_count = unknown_shrimp + unknown_fish
        
        # Get recent records for display (5 most recent from each collection)
        recent_shrimp = list(shrimp_collection.find(query).sort('timestamp', -1).limit(5))
        recent_fish = list(fish_collection.find(query).sort('timestamp', -1).limit(5))
        
        # Combine and sort by timestamp
        combined_recent = recent_shrimp + recent_fish
        combined_recent.sort(key=lambda x: x['timestamp'], reverse=True)
        combined_recent = combined_recent[:5]  # Get only the 5 most recent
        
        # Format records for JSON
        formatted_recent = []
        for record in combined_recent:
            # Get farm info from record or metadata
            farm_name = record.get('farm_name', '')
            if not farm_name and 'metadata' in record:
                farm_name = record['metadata'].get('farm_name', '')
                
            formatted_recent.append({
                'id': str(record['_id']),
                'filename': os.path.basename(record['filepath']),
                'type': record.get('type', 'unknown'),
                'health_status': record['health_status'],
                'timestamp': record['timestamp'].strftime('%Y-%m-%d %H:%M'),
                'is_healthy': record['health_status'] == 'Healthy',
                'farm_name': farm_name
            })
        
        # Get farms count - for full dashboard only
        farms_count = db.farms.count_documents({"user_id": user_id})
        
        # If specific farm is selected, get farm name
        selected_farm_name = "All Farms"
        if farm_id != 'all':
            farm_doc = db.farms.find_one({"_id": ObjectId(farm_id), "user_id": user_id})
            if farm_doc:
                selected_farm_name = farm_doc.get('farm_name', 'Unknown Farm')
        
        # Generate farm-specific trend data
        # For a real implementation, you would query the database to get actual historical data
        if farm_id != 'all':
            # This is a simplified version for demonstration
            # In a real app, you would query by date ranges to get actual historical data
            trend_data = {
                'months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                'shrimp_counts': [
                    max(0, round(total_shrimp * 0.2)),
                    max(0, round(total_shrimp * 0.3)),
                    max(0, round(total_shrimp * 0.5)),
                    max(0, round(total_shrimp * 0.7)),
                    max(0, round(total_shrimp * 0.9)),
                    total_shrimp
                ],
                'fish_counts': [
                    max(0, round(total_fish * 0.1)),
                    max(0, round(total_fish * 0.3)),
                    max(0, round(total_fish * 0.4)),
                    max(0, round(total_fish * 0.6)),
                    max(0, round(total_fish * 0.8)),
                    total_fish
                ],
                'healthy_counts': [
                    max(0, round(healthy_count * 0.2)),
                    max(0, round(healthy_count * 0.3)),
                    max(0, round(healthy_count * 0.5)),
                    max(0, round(healthy_count * 0.7)),
                    max(0, round(healthy_count * 0.9)),
                    healthy_count
                ],
                'unhealthy_counts': [
                    max(0, round(unhealthy_count * 0.1)),
                    max(0, round(unhealthy_count * 0.2)),
                    max(0, round(unhealthy_count * 0.3)),
                    max(0, round(unhealthy_count * 0.4)),
                    max(0, round(unhealthy_count * 0.6)),
                    unhealthy_count
                ]
            }
        else:
            # Default trend data for all farms
            trend_data = {
                'months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                'shrimp_counts': [12, 19, 15, 17, 22, total_shrimp],
                'fish_counts': [8, 15, 12, 14, 18, total_fish],
                'healthy_counts': [15, 25, 20, 22, 30, healthy_count],
                'unhealthy_counts': [5, 9, 7, 9, 10, unhealthy_count]
            }
        
        # Return JSON response
        return jsonify({
            'stats': {
                'total_count': total_count,
                'healthy_count': healthy_count,
                'unhealthy_count': unhealthy_count,
                'unknown_count': unknown_count,
                'reports_count': total_count,  # Assuming all analyses have reports
                'shrimp_count': total_shrimp,
                'fish_count': total_fish,
                'farms_count': farms_count,
                'selected_farm': selected_farm_name
            },
            'recent_analyses': formatted_recent,
            'trend_data': trend_data
        })
    except Exception as e:
        print(f"Error in dashboard_data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/export-csv')
@login_required
def export_analysis_csv():
    """Export analysis data as CSV"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get query parameters
        type_filter = request.args.get('type', 'all')
        status_filter = request.args.get('status', 'all')
        date_filter = request.args.get('date', 'all')
        search_term = request.args.get('search', '')
        farm_id = request.args.get('farm_id', 'all')
        
        # Build base query
        base_query = {"user_id": user_id}
        
        # Add farm filter
        if farm_id != 'all':
            base_query['$or'] = [
                {'farm_id': farm_id},
                {'metadata.farm_id': farm_id}
            ]
        
        # Build date filter
        if date_filter != 'all':
            end_date = datetime.utcnow()
            if date_filter == 'today':
                start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
            elif date_filter == 'week':
                start_date = end_date - timedelta(days=7)
            elif date_filter == 'month':
                start_date = end_date - timedelta(days=30)
            elif date_filter == 'quarter':
                start_date = end_date - timedelta(days=90)
            else:
                start_date = datetime(2000, 1, 1)  # Default to a very old date
                
            date_query = {'timestamp': {'$gte': start_date, '$lte': end_date}}
            # Merge date query with base query
            if '$or' in base_query:
                date_base_query = base_query.copy()
                date_base_query.update(date_query)
            else:
                date_base_query = {**base_query, **date_query}
        else:
            date_base_query = base_query
        
        # Build status filter
        if status_filter != 'all':
            if status_filter == 'healthy':
                status_query = {'health_status': 'Healthy'}
            elif status_filter == 'unhealthy':
                status_query = {'health_status': {'$ne': 'Healthy'}}
            else:
                status_query = {'health_status': status_filter.capitalize()}
            
            # Merge status query with base+date query
            if '$or' in date_base_query:
                status_date_base_query = date_base_query.copy()
                status_date_base_query.update(status_query)
            else:
                status_date_base_query = {**date_base_query, **status_query}
        else:
            status_date_base_query = date_base_query
        
        # Build search filter
        if search_term:
            search_query = {'$or': [
                {'filename': {'$regex': search_term, '$options': 'i'}},
                {'health_status': {'$regex': search_term, '$options': 'i'}},
                {'farm_name': {'$regex': search_term, '$options': 'i'}},
                {'metadata.farm_name': {'$regex': search_term, '$options': 'i'}}
            ]}
            
            # Merge search query with other queries
            if '$or' in status_date_base_query:
                final_query = status_date_base_query.copy()
                final_query['$and'] = [{'$or': final_query.pop('$or')}, search_query]
            else:
                final_query = {**status_date_base_query, **search_query}
        else:
            final_query = status_date_base_query
        
        # Get records based on type
        if type_filter == 'shrimp':
            records = list(shrimp_collection.find(final_query).sort('timestamp', -1))
        elif type_filter == 'fish':
            records = list(fish_collection.find(final_query).sort('timestamp', -1))
        else:
            shrimp_records = list(shrimp_collection.find(final_query).sort('timestamp', -1))
            fish_records = list(fish_collection.find(final_query).sort('timestamp', -1))
            
            # Add type field to each record
            for record in shrimp_records:
                record['type'] = 'shrimp'
            for record in fish_records:
                record['type'] = 'fish'
                
            records = shrimp_records + fish_records
            # Sort combined records by timestamp
            records.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Create CSV content
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Type', 'Filename', 'Farm', 'Health Status', 'Confidence', 'Date', 'Time'])
        
        # Write data rows
        for record in records:
            date_str = record['timestamp'].strftime('%Y-%m-%d')
            time_str = record['timestamp'].strftime('%H:%M:%S')
            
            # Get farm name from record or metadata
            farm_name = record.get('farm_name', '')
            if not farm_name and 'metadata' in record:
                farm_name = record['metadata'].get('farm_name', '')
            
            writer.writerow([
                str(record['_id']),
                record.get('type', 'unknown'),
                os.path.basename(record['filepath']),
                farm_name,
                record['health_status'],
                f"{record.get('confidence', 0) * 100:.1f}%" if 'confidence' in record else 'N/A',
                date_str,
                time_str
            ])
        
        # Prepare response
        output.seek(0)
        filename = f"aquaculture_data_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment;filename={filename}",
                "Content-Type": "text/csv"
            }
        )
        
    except Exception as e:
        print(f"Error in export_analysis_csv: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/export-batch', methods=['POST'])
@login_required
def export_batch_reports():
    """API endpoint to export multiple reports as a ZIP file"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get the list of record IDs from request
        data = request.json
        record_ids = data.get('record_ids', [])
        record_type = data.get('type', 'all')  # 'fish', 'shrimp', or 'all'
        
        if not record_ids:
            return jsonify({"error": "No record IDs provided"}), 400
        
        # Create a temporary directory for reports
        temp_dir = tempfile.mkdtemp()
        zip_filename = f"batch_reports_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
        zip_path = os.path.join(temp_dir, zip_filename)
        
        # Create a ZIP file
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            # Process shrimp records
            if record_type in ['all', 'shrimp']:
                for record_id in record_ids:
                    try:
                        record = shrimp_collection.find_one({
                            "_id": ObjectId(record_id),
                            "user_id": user_id
                        })
                        if record:
                            # Generate report content
                            report_content = generate_shrimp_report_content(record)
                            
                            # Add to ZIP
                            report_filename = f"shrimp_report_{record_id}.txt"
                            zipf.writestr(report_filename, report_content)
                    except Exception as e:
                        print(f"Error processing shrimp record {record_id}: {str(e)}")
            
            # Process fish records
            if record_type in ['all', 'fish']:
                for record_id in record_ids:
                    try:
                        record = fish_collection.find_one({
                            "_id": ObjectId(record_id),
                            "user_id": user_id
                        })
                        if record:
                            # Generate report content
                            report_content = generate_fish_report_content(record)
                            
                            # Add to ZIP
                            report_filename = f"fish_report_{record_id}.txt"
                            zipf.writestr(report_filename, report_content)
                    except Exception as e:
                        print(f"Error processing fish record {record_id}: {str(e)}")
        
        # Save ZIP metadata in database
        report_id = report_collection.insert_one({
            'name': 'Batch Reports',
            'type': 'batch',
            'format': 'zip',
            'filepath': zip_path,
            'timestamp': datetime.utcnow(),
            'user_id': user_id
        }).inserted_id
        
        # Send the file
        return send_from_directory(
            directory=os.path.dirname(zip_path),
            path=os.path.basename(zip_path),
            as_attachment=True
        )
        
    except Exception as e:
        print(f"Error in export_batch_reports: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/recent-reports')
@login_required
def get_recent_reports():
    """API endpoint to get the most recent reports"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get the 10 most recent reports for this user
        recent_reports = list(report_collection.find({"user_id": user_id}).sort('timestamp', -1).limit(10))
        
        # Format for JSON response
        formatted_reports = []
        for report in recent_reports:
            # Check if the file exists
            file_exists = os.path.exists(report['filepath'])
            
            formatted_reports.append({
                'id': str(report['_id']),
                'name': report['name'],
                'generated_date': report['timestamp'].strftime('%Y-%m-%d %H:%M'),
                'type': report['type'],
                'format': report['format'].upper(),
                'download_url': f"/download_report/{str(report['_id'])}",
                'file_exists': file_exists,  # Add this for debugging
                'farm_name': report.get('farm_name', 'N/A')
            })
        
        return jsonify({'reports': formatted_reports})
        
    except Exception as e:
        print(f"Error fetching recent reports: {str(e)}")
        return jsonify({'reports': [], 'error': str(e)})

@app.route('/api/export-statistics')
@login_required
def export_statistics():
    """Export statistics data as CSV"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get query parameters
        time_range = request.args.get('timeRange', 'month')
        organism_filter = request.args.get('organism', 'all')
        farm_id = request.args.get('farm_id', 'all')
        
        # Build base query
        base_query = {"user_id": user_id}
        
        # Add farm filter
        if farm_id != 'all':
            base_query['$or'] = [
                {'farm_id': farm_id},
                {'metadata.farm_id': farm_id}
            ]
        
        # Calculate the date range based on the time range
        end_date = datetime.utcnow()
        if time_range == 'week':
            start_date = end_date - timedelta(days=7)
            time_period = 'Last Week'
        elif time_range == 'month':
            start_date = end_date - timedelta(days=30)
            time_period = 'Last Month'
        elif time_range == 'quarter':
            start_date = end_date - timedelta(days=90)
            time_period = 'Last Quarter'
        elif time_range == 'year':
            start_date = end_date - timedelta(days=365)
            time_period = 'Last Year'
        else:  # 'all'
            start_date = datetime(2000, 1, 1)
            time_period = 'All Time'
        
        # Add date filter to query
        date_query = {'timestamp': {'$gte': start_date, '$lte': end_date}}
        
        # Merge date with base query
        if '$or' in base_query:
            final_query = base_query.copy()
            final_query.update(date_query)
        else:
            final_query = {**base_query, **date_query}
        
        # Add organism filter
        if organism_filter == 'fish':
            fish_data = list(fish_collection.find(final_query))
            shrimp_data = []
        elif organism_filter == 'shrimp':
            fish_data = []
            shrimp_data = list(shrimp_collection.find(final_query))
        else:  # 'all'
            fish_data = list(fish_collection.find(final_query))
            shrimp_data = list(shrimp_collection.find(final_query))
        
        all_data = fish_data + shrimp_data
        
        # Get farm name if farm_id is provided
        farm_name = "All Farms"
        if farm_id != 'all':
            farm_doc = db.farms.find_one({"_id": ObjectId(farm_id), "user_id": user_id})
            if farm_doc:
                farm_name = farm_doc.get('farm_name', 'Unknown Farm')
        
        # Create a CSV file
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header row
        writer.writerow(['Aquaculture Health Monitoring System - Statistics Export'])
        writer.writerow(['Time Period:', time_period])
        writer.writerow(['Organism Filter:', organism_filter.capitalize()])
        writer.writerow(['Farm:', farm_name])
        writer.writerow(['Export Date:', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow([])  # Empty row
        
        # Write summary statistics
        writer.writerow(['Summary Statistics'])
        writer.writerow(['Total Analyses:', len(all_data)])
        writer.writerow(['Fish Analyses:', len(fish_data)])
        writer.writerow(['Shrimp Analyses:', len(shrimp_data)])
        writer.writerow(['Healthy:', sum(1 for record in all_data if record.get('health_status') == 'Healthy')])
        writer.writerow(['Unhealthy:', sum(1 for record in all_data if record.get('health_status') not in ['Healthy', 'Unknown'])])
        writer.writerow(['Unknown:', sum(1 for record in all_data if record.get('health_status') == 'Unknown')])
        writer.writerow([])  # Empty row
        
        # Write detailed data
        writer.writerow(['Detailed Analysis Data'])
        writer.writerow(['ID', 'Type', 'Health Status', 'Farm', 'Confidence', 'Timestamp'])
        
        for record in all_data:
            # Get farm name from record or metadata
            record_farm = record.get('farm_name', '')
            if not record_farm and 'metadata' in record:
                record_farm = record['metadata'].get('farm_name', '')
                
            writer.writerow([
                str(record['_id']),
                record.get('type', 'unknown'),
                record.get('health_status', 'N/A'),
                record_farm,
                f"{record.get('confidence', 0) * 100:.1f}%" if 'confidence' in record else 'N/A',
                record['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            ])
        
        # Prepare the response
        output.seek(0)
        filename = f"aquaculture_statistics_{time_range}_{organism_filter}_{end_date.strftime('%Y%m%d')}.csv"
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment;filename={filename}",
                "Content-Type": "text/csv"
            }
        )
    except Exception as e:
        print(f"Error exporting statistics: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/generate_report/<analysis_type>/<record_id>')
@login_required
def generate_report(analysis_type, record_id):
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get the record from the appropriate collection
        if analysis_type == 'shrimp':
            record = shrimp_collection.find_one({
                "_id": ObjectId(record_id),
                "user_id": user_id
            })
            report_content = generate_shrimp_report_content(record)
        else:  # fish
            record = fish_collection.find_one({
                "_id": ObjectId(record_id),
                "user_id": user_id
            })
            report_content = generate_fish_report_content(record)
        
        if not record:
            return "Result not found", 404
            
        # Get farm information
        farm_name = record.get('farm_name', '')
        farm_id = record.get('farm_id', '')
        farm_location = record.get('farm_location', '')
        
        if not farm_name and 'metadata' in record:
            farm_name = record['metadata'].get('farm_name', '')
            farm_id = record['metadata'].get('farm_id', '')
            farm_location = record['metadata'].get('farm_location', '')
            
        # Generate unique filename for the report
        report_filename = f"{record.get('type', analysis_type)}_health_report_{str(record['_id'])}.txt"
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
        
        # Write report to file
        with open(report_path, 'w') as f:
            f.write(report_content)
        
        # Log the report in the database
        report_id = report_collection.insert_one({
            'name': f"{analysis_type.capitalize()} Health Report - {farm_name}",
            'type': 'health',
            'format': 'txt',
            'filepath': report_path,
            'timestamp': datetime.utcnow(),
            'farm_id': farm_id,
            'farm_name': farm_name,
            'farm_location': farm_location,
            'user_id': user_id
        }).inserted_id
        
        # Send the file
        return send_from_directory(
            directory=app.config['UPLOAD_FOLDER'], 
            path=report_filename,
            as_attachment=True
        )
    
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return f"Error generating report: {str(e)}", 500

# Helper functions for report generation
def generate_shrimp_report_content(record):
    """Generate report content for a shrimp record"""
    report_date = record["timestamp"].strftime("%Y-%m-%d")
    report_time = record["timestamp"].strftime("%H:%M:%S")
    
    # Get farm information
    farm_name = record.get('farm_name', 'N/A')
    farm_id = record.get('farm_id', 'N/A')
    farm_location = record.get('farm_location', 'N/A')
    
    # If there's no direct farm info, check metadata
    if farm_name == 'N/A' and 'metadata' in record:
        farm_name = record['metadata'].get('farm_name', 'N/A')
        farm_id = record['metadata'].get('farm_id', 'N/A')
        farm_location = record['metadata'].get('farm_location', 'N/A')
    
    # Get suggestion based on health status
    suggestion = shrimp_disease_suggestions.get(record["health_status"], "No specific suggestion available.")
    
    # Trade value assessment based on health status
    trade_value = "Excellent market value. Certified healthy specimen suitable for premium pricing and export markets." if record["health_status"] == "Healthy" else "Reduced market value. Recommended for local market only with appropriate treatment documentation."
    
    report_content = f"""
AQUACULTURE HEALTH REPORT
=========================
Date: {report_date}
Time: {report_time}
Sample ID: {str(record['_id'])}
Farm: {farm_name}
Farm ID: {farm_id}
Farm Location: {farm_location}
Type: SHRIMP
Health Status: {record['health_status']}
{"Confidence: " + str(round(record.get('confidence', 0) * 100, 1)) + "%" if 'confidence' in record else ""}

RECOMMENDATIONS:
{suggestion}

TRADING VALUE ASSESSMENT:
{trade_value}
    """
    
    return report_content

def generate_fish_report_content(record):
    """Generate report content for a fish record"""
    report_date = record["timestamp"].strftime("%Y-%m-%d")
    report_time = record["timestamp"].strftime("%H:%M:%S")
    
    # Get farm information
    farm_name = record.get('farm_name', 'N/A')
    farm_id = record.get('farm_id', 'N/A')
    farm_location = record.get('farm_location', 'N/A')
    
    # If there's no direct farm info, check metadata
    if farm_name == 'N/A' and 'metadata' in record:
        farm_name = record['metadata'].get('farm_name', 'N/A')
        farm_id = record['metadata'].get('farm_id', 'N/A')
        farm_location = record['metadata'].get('farm_location', 'N/A')
    
    # Get suggestion based on health status
    suggestion = fish_disease_suggestions.get(record["health_status"], "No specific suggestion available.")
    
    # Trade value assessment based on health status
    trade_value = "Excellent market value. Certified healthy specimen suitable for premium pricing and export markets." if record["health_status"] == "Healthy" else "Reduced market value. Recommended for local market only with appropriate treatment documentation."
    
    report_content = f"""
AQUACULTURE HEALTH REPORT
=========================
Date: {report_date}
Time: {report_time}
Sample ID: {str(record['_id'])}
Farm: {farm_name}
Farm ID: {farm_id}
Farm Location: {farm_location}
Type: FISH
Health Status: {record['health_status']}
{"Confidence: " + str(round(record.get('confidence', 0) * 100, 1)) + "%" if 'confidence' in record else ""}

RECOMMENDATIONS:
{suggestion}

TRADING VALUE ASSESSMENT:
{trade_value}
    """
    
    return report_content

# Page routes
@app.route('/reports')
@login_required
def reports_page():
    """Render the reports page"""
    return render_template('reports.html')

@app.route('/statistics')
@login_required
def statistics_page():
    """Render the statistics page"""
    return render_template('statistics.html')

@app.route('/settings')
@login_required
def settings_page():
    """Render the settings page"""
    return render_template('settings.html')

@app.route('/history')
@login_required
def history():
    """Render the analysis history page"""
    try:
        # Get user information from session
        user = session.get('user')
        if not user:
            # If user is not in session, redirect to login page
            flash('Please log in to access the history page.', 'error')
            return redirect(url_for('index'))
            
        # Return the history template with user info
        return render_template('history.html', user=user)
    except Exception as e:
        print(f"History page error: {str(e)}")
        flash('An error occurred while loading the history page.', 'error')
        return redirect(url_for('index'))

@app.route('/download_report/<report_id>')
@login_required
def download_report(report_id):
    """Download a previously generated report"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Find the report in the database
        report = report_collection.find_one({
            "_id": ObjectId(report_id),
            "user_id": user_id
        })
        
        if not report:
            return "Report not found", 404
        
        # Get the filename
        report_path = report['filepath']
        filename = os.path.basename(report_path)
        
        # Check if file exists
        if not os.path.exists(report_path):
            print(f"File not found: {report_path}")
            return "Report file not found on server", 404
        
        # Return the file for download
        return send_from_directory(
            directory=os.path.dirname(report_path), 
            path=filename,
            as_attachment=True
        )
    
    except Exception as e:
        print(f"Error downloading report: {str(e)}")
        return f"Error downloading report: {str(e)}", 500
@app.route('/api/statistics')
@login_required
def get_statistics():
    """API endpoint to provide statistics data for the statistics page"""
    try:
        # Get user ID
        user_id = session.get('user', {}).get('id')
        if not user_id:
            return jsonify({"error": "User not authenticated"}), 401
            
        # Get query parameters
        time_range = request.args.get('timeRange', 'month')
        organism = request.args.get('organism', 'all')
        farm_id = request.args.get('farm_id', 'all')
        
        # Build base query for this user
        base_query = {"user_id": user_id}
        
        # Add farm filter if provided
        if farm_id != 'all':
            base_query['$or'] = [
                {'farm_id': farm_id},
                {'metadata.farm_id': farm_id}
            ]
            
        # Calculate date range based on time_range
        end_date = datetime.utcnow()
        if time_range == 'week':
            start_date = end_date - timedelta(days=7)
        elif time_range == 'month':
            start_date = end_date - timedelta(days=30)
        elif time_range == 'quarter':
            start_date = end_date - timedelta(days=90)
        elif time_range == 'year':
            start_date = end_date - timedelta(days=365)
        else:  # 'all'
            start_date = datetime(2000, 1, 1)
            
        # Add date range to query
        date_query = {'timestamp': {'$gte': start_date, '$lte': end_date}}
        if '$or' in base_query:
            query = base_query.copy()
            query.update(date_query)
        else:
            query = {**base_query, **date_query}
            
        # Modify query based on organism filter
        if organism != 'all':
            # We'll query the appropriate collection based on organism type
            pass
        
        # Get all records within the date range
        shrimp_records = list(shrimp_collection.find(query)) if organism in ['all', 'shrimp'] else []
        fish_records = list(fish_collection.find(query)) if organism in ['all', 'fish'] else []
        
        # Process records for health trend data (by month)
        months = {}
        for record in shrimp_records + fish_records:
            month = record['timestamp'].strftime('%b %Y')
            if month not in months:
                months[month] = {'healthy': 0, 'unhealthy': 0, 'unknown': 0}
                
            if record['health_status'] == 'Healthy':
                months[month]['healthy'] += 1
            elif record['health_status'] == 'Unknown':
                months[month]['unknown'] += 1
            else:
                months[month]['unhealthy'] += 1
                
        # Sort months chronologically
        sorted_months = sorted(months.keys(), key=lambda x: datetime.strptime(x, '%b %Y'))
        
        # Create health trend data structure
        health_trend = {
            'labels': sorted_months,
            'healthy': [months[month]['healthy'] for month in sorted_months],
            'unhealthy': [months[month]['unhealthy'] for month in sorted_months],
            'unknown': [months[month]['unknown'] for month in sorted_months]
        }
        
        # Create species distribution data
        total_shrimp = len(shrimp_records)
        total_fish = len(fish_records)
        species_distribution = {
            'labels': ['Fish', 'Shrimp'],
            'values': [total_fish, total_shrimp]
        }
        
        # Create health distribution data
        total_healthy = sum(1 for r in shrimp_records + fish_records if r['health_status'] == 'Healthy')
        total_unhealthy = sum(1 for r in shrimp_records + fish_records if r['health_status'] not in ['Healthy', 'Unknown'])
        total_unknown = sum(1 for r in shrimp_records + fish_records if r['health_status'] == 'Unknown')
        
        health_distribution = {
            'labels': ['Healthy', 'Unhealthy', 'Unknown'],
            'values': [total_healthy, total_unhealthy, total_unknown]
        }
        
        # Create confidence data (mock data as example)
        confidence_ranges = ['90-100%', '80-90%', '70-80%', '60-70%', '50-60%', '<50%']
        confidence_counts = [0, 0, 0, 0, 0, 0]
        
        # Count records by confidence level
        for record in shrimp_records:
            if 'confidence' in record:
                conf = record['confidence'] * 100  # Convert to percentage
                if conf >= 90:
                    confidence_counts[0] += 1
                elif conf >= 80:
                    confidence_counts[1] += 1
                elif conf >= 70:
                    confidence_counts[2] += 1
                elif conf >= 60:
                    confidence_counts[3] += 1
                elif conf >= 50:
                    confidence_counts[4] += 1
                else:
                    confidence_counts[5] += 1
        
        confidence_data = {
            'labels': confidence_ranges,
            'values': confidence_counts
        }
        
        # Return all data in a single response
        return jsonify({
            'healthTrend': health_trend,
            'speciesDistribution': species_distribution,
            'healthDistribution': health_distribution,
            'confidenceData': confidence_data
        })
        
    except Exception as e:
        print(f"Error fetching statistics data: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Clear any session files
    import os
    import glob
    session_path = os.path.join(tempfile.gettempdir(), 'flask_session_*')
    for session_file in glob.glob(session_path):
        try:
            os.remove(session_file)
        except:
            pass
            
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
    init_db()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)