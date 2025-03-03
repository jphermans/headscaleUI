import os
import requests
from flask import Flask, render_template, redirect, url_for, flash, session, jsonify
from flask_wtf import FlaskForm
from wtforms.fields.choices import SelectField
from wtforms.fields.simple import StringField, SubmitField
from wtforms.validators import DataRequired
from forms import UserForm, NodeForm, APIKeyForm, LoginForm
from dotenv import load_dotenv
from functools import wraps
from datetime import timedelta, datetime

# 🔥 Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)  # Session expires after 12 hours
app.config['SESSION_COOKIE_SECURE'] = False  # Allow cookies over HTTP during development
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie

# 🔗 Get Headscale API details from .env
HEADSCALE_URL = os.getenv("HEADSCALE_URL")

# 🛠 API Helper Functions
def handle_api_response(response):
    """Handle common API response status codes."""
    try:
        if response.status_code == 401:  # Unauthorized - key expired or invalid
            session.pop('api_key', None)
            raise requests.exceptions.RequestException("Session expired. Please login again.")
        elif response.status_code == 404:  # Not found
            raise requests.exceptions.RequestException("Resource not found")
        elif response.status_code == 500:  # Server error
            raise requests.exceptions.RequestException("Internal server error")
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise requests.exceptions.RequestException(f"HTTP Error: {str(e)}")

def get_headscale_data(endpoint):
    """Fetch data from the Headscale API."""
    url = f"{HEADSCALE_URL}{endpoint}"
    try:
        headers = {"Authorization": f"Bearer {session['api_key']}"}
        response = requests.get(url, headers=headers, timeout=5)
        handle_api_response(response)
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return {}, str(e)

def post_headscale_data(endpoint, data):
    """Send data to the Headscale API."""
    url = f"{HEADSCALE_URL}{endpoint}"
    try:
        headers = {"Authorization": f"Bearer {session['api_key']}"}
        response = requests.post(url, json=data, headers=headers, timeout=5)
        handle_api_response(response)
        return response.json(), None
    except requests.exceptions.RequestException as e:
        return {}, str(e)

def delete_headscale_data(endpoint):
    """Delete data via the Headscale API."""
    url = f"{HEADSCALE_URL}{endpoint}"
    try:
        headers = {"Authorization": f"Bearer {session['api_key']}"}
        # For API key deletion, use a different endpoint format
        if 'apikey' in endpoint:
            # Use the prefix directly from the URL
            key_prefix = endpoint.split('/')[-1]
            delete_url = f"{HEADSCALE_URL}/api/v1/apikey/{key_prefix}"
            print(f"[DEBUG] Attempting to delete API key with URL: {delete_url}")
            delete_response = requests.delete(delete_url, headers=headers, timeout=5)
            
            print(f"[DEBUG] Delete response status: {delete_response.status_code}")
            print(f"[DEBUG] Delete response body: {delete_response.text}")
            
            if delete_response.status_code in [200, 201, 204, 404]:  # Include 404 as success case
                return {}, None
            else:
                print(f"[ERROR] Failed to delete key: {delete_response.text}")
                return {}, f"Failed to delete key: {delete_response.text}"
        else:
            response = requests.delete(url, headers=headers, timeout=5)
            print(f"[DEBUG] Response status code: {response.status_code}")
            print(f"[DEBUG] Response headers: {dict(response.headers)}")
            print(f"[DEBUG] Response body: {response.text}\n")

        # Check response status
        if response.status_code in [200, 204, 201]:
            return {}, None
        elif response.status_code == 500:
            app.logger.error(f"Server error when deleting: {url}, Status: {response.status_code}, Response: {response.text}")
            print(f"[ERROR] Server error: {response.text}")
            return {}, "Internal server error occurred"
        elif response.status_code == 404:
            print(f"[ERROR] Resource not found: {response.text}")
            return {}, "Resource not found"
        elif response.status_code == 401:
            session.pop('api_key', None)
            print(f"[ERROR] Authentication failed: {response.text}")
            return {}, "Session expired. Please login again."
        else:
            app.logger.error(f"Unexpected status code: {response.status_code}, Response: {response.text}")
            print(f"[ERROR] Unexpected error: Status {response.status_code}, Response: {response.text}")
            return {}, f"Error: {response.status_code} - {response.text}"
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request exception when deleting: {url}, Error: {str(e)}")
        print(f"[ERROR] Request exception: {str(e)}")
        return {}, str(e)

# 📋 WTForms for input handling
class UserForm(FlaskForm):
    name = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Add User")

class NodeForm(FlaskForm):
    name = StringField("Node Name", validators=[DataRequired()])
    user = SelectField("Assign to User", validators=[DataRequired()], choices=[])
    submit = SubmitField("Add Node")

class APIKeyForm(FlaskForm):
    description = StringField("Description", validators=[DataRequired()])
    validity = SelectField(
        "Validity Period",
        choices=[
            ("87600h", "10 Years"),
            ("8760h", "1 Year"),
            ("720h", "30 Days"),
            ("168h", "7 Days"),
            ("24h", "1 Day"),
        ],
        default="8760h",
        validators=[DataRequired()]
    )
    submit = SubmitField("Generate API Key")

# Move login_required decorator to the top, before the routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'api_key' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        
        # Check if the API key is still valid
        headers = {"Authorization": f"Bearer {session['api_key']}"}
        try:
            response = requests.get(f"{HEADSCALE_URL}/api/v1/apikey", headers=headers, timeout=5)
            if response.status_code == 401:  # Unauthorized - key expired or invalid
                session.pop('api_key', None)
                flash('Your session has expired. Please login again.', 'warning')
                return redirect(url_for('login'))
            elif response.status_code != 200:
                flash('Error validating session. Please try again.', 'danger')
                return redirect(url_for('login'))
        except requests.exceptions.RequestException:
            flash('Error connecting to Headscale server', 'danger')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Context processor to add year to all templates
@app.context_processor
def inject_year():
    return {'year': datetime.now().year}

# Then all the routes follow...
@app.route('/')
@login_required
def index():
    """Display the homepage with a menu."""
    return render_template('index.html')

@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    """Manage users."""
    form = UserForm()
    if form.validate_on_submit():
        result, error = post_headscale_data(
            "/api/v1/user",
            {"name": form.name.data}
        )
        if error:
            flash(f"Error adding user: {error}", "danger")
        else:
            flash(f"User {form.name.data} added!", "success")
        return redirect(url_for('users'))

    users_data, error = get_headscale_data("/api/v1/user")
    if error:
        flash(f"Error fetching users: {error}", "danger")
        users_list = []
    else:
        users_list = users_data.get("users", [])
    return render_template('users.html', users=users_list, form=form)

@app.route('/delete_user/<string:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete a user."""
    result, error = delete_headscale_data(f"/api/v1/user/{user_id}")
    if error:
        flash(f"Error deleting user: {error}", "danger")
    else:
        flash("User deleted successfully", "success")
    return redirect(url_for('users'))

@app.route('/nodes', methods=['GET', 'POST'])
@login_required
def nodes():
    """Manage nodes grouped by user."""
    users_data, error = get_headscale_data("/api/v1/user")
    nodes_data, nodes_error = get_headscale_data("/api/v1/node")
    
    users = users_data.get("users", [])
    nodes = nodes_data.get("nodes", [])

    if error:
        flash(f"Error fetching users: {error}", "danger")
    if nodes_error:
        flash(f"Error fetching nodes: {nodes_error}", "danger")

    # Prepare form for adding new nodes
    form = NodeForm()
    form.user.choices = [(str(user["id"]), user["name"]) for user in users]

    if form.validate_on_submit():
        result, error = post_headscale_data(
            "/api/v1/node",
            {
                "name": form.name.data,
                "user_id": int(form.user.data)  # Convert string ID back to int
            }
        )
        if error:
            flash(f"Error adding node: {error}", "danger")
        else:
            flash(f"Node {form.name.data} added!", "success")
        return redirect(url_for('nodes'))

    # Group nodes by user
    nodes_by_user = {}
    for node in nodes:
        user_info = node.get("user", {})
        user_id = user_info.get("id") if isinstance(user_info, dict) else user_info

        if user_id:
            if user_id not in nodes_by_user:
                nodes_by_user[user_id] = []
            nodes_by_user[user_id].append(node)

    return render_template(
        'nodes.html',
        users=users,
        nodes_by_user=nodes_by_user,
        form=form
    )

@app.route('/delete_node/<string:node_id>', methods=['POST'])
@login_required
def delete_node(node_id):
    """Delete a node."""
    result, error = delete_headscale_data(f"/api/v1/node/{node_id}")
    if error:
        flash(f"Error deleting node: {error}", "danger")
    else:
        flash("Node deleted successfully", "success")
    return redirect(url_for('nodes'))

@app.route('/help')
def help():
    """Display the help documentation."""
    return render_template('help.html')

@app.route('/apikeys', methods=['GET', 'POST'])
@login_required
def apikeys():
    """Manage API Keys."""
    form = APIKeyForm()
    if form.validate_on_submit():
        result, error = post_headscale_data(
            "/api/v1/apikey",
            {
                "description": form.description.data,
                "expiration": form.validity.data
            }
        )
        if error:
            flash(f"Error generating API key: {error}", "danger")
        else:
            key = result.get("apiKey", {}).get("key", "")
            if key:
                flash(
                    f"API Key generated successfully. Key: {key}\n"
                    "Please save this key now - it won't be shown again!",
                    "success"
                )
            else:
                flash("API Key generated but no key returned", "warning")
        return redirect(url_for('apikeys'))

    api_keys, error = get_headscale_data("/api/v1/apikey")
    if error:
        flash(f"Error fetching API keys: {error}", "danger")
        keys_list = []
    else:
        keys_list = api_keys.get("apiKeys", [])
    return render_template('apikeys.html', api_keys=keys_list, form=form)

@app.route('/delete_apikey/<string:key_id>', methods=['POST'])
@login_required
def delete_apikey(key_id):
    """Delete an API Key."""
    print(f"\n[DEBUG] Starting API key deletion for key_id: {key_id}")
    
    try:
        current_key_id = int(session.get('api_key_id', 0))
    except (ValueError, TypeError):
        current_key_id = 0
    
    # Don't allow deletion of the current key
    if str(current_key_id) == str(key_id):
        print(f"[DEBUG] Attempted to delete current key (key_id: {key_id})")
        flash("Cannot delete the API key that you're currently using", 'warning')
        return redirect(url_for('apikeys'))

    # Attempt to delete the key
    print(f"[DEBUG] Calling delete_headscale_data with endpoint: /api/v1/apikey/{key_id}")
    print(f"[DEBUG] Current session key_id: {current_key_id}, Type: {type(current_key_id)}")
    print(f"[DEBUG] Key to delete: {key_id}")
    
    data, error = delete_headscale_data(f"/api/v1/apikey/{key_id}")
    if error:
        if "not found" in str(error).lower():
            flash("API key not found", 'warning')
        else:
            app.logger.error(f"Failed to delete API key {key_id}: {error}")
            flash(f"Error deleting API key: {error}", 'danger')
    else:
        app.logger.info(f"Successfully deleted API key {key_id}")
        print("[DEBUG] Delete operation successful")
        flash('API key deleted successfully', 'success')
    
    return redirect(url_for('apikeys'))

@app.route('/mark_welcome_shown')
def mark_welcome_shown():
    """Mark the welcome message as shown for this session."""
    session['shown_welcome'] = True
    return jsonify({'success': True})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'api_key' in session:
        return redirect(url_for('index'))
        
    form = LoginForm()
    if form.validate_on_submit():
        api_key = form.api_key.data.strip()
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            response = requests.get(f"{HEADSCALE_URL}/api/v1/apikey", headers=headers, timeout=5)
            
            if response.status_code == 200:
                # Find the current key's ID from the response
                api_keys = response.json().get('apiKeys', [])
                current_key = None
                for key in api_keys:
                    test_key = f"{key['prefix']}"
                    if api_key.startswith(test_key):
                        current_key = key
                        break
                
                if current_key:
                    session.clear()
                    session['api_key'] = api_key
                    session['api_key_id'] = int(current_key['id'])
                    session['shown_welcome'] = False  # Initialize welcome message flag
                    session.permanent = True
                    flash('Login successful!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Could not verify API key', 'danger')
            elif response.status_code == 401:
                flash('Invalid API key or key has expired', 'danger')
            else:
                flash(f'Error: Server returned status code {response.status_code}', 'danger')
        except requests.exceptions.RequestException as e:
            flash(f'Error connecting to Headscale server: {str(e)}', 'danger')
        
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('api_key', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/check_session')
def check_session():
    """Check if the current session is still valid."""
    if 'api_key' not in session:
        return jsonify({'valid': False})
        
    headers = {"Authorization": f"Bearer {session['api_key']}"}
    try:
        response = requests.get(f"{HEADSCALE_URL}/api/v1/apikey", headers=headers, timeout=5)
        return jsonify({'valid': response.status_code == 200})
    except requests.exceptions.RequestException:
        return jsonify({'valid': False})

@app.route('/health')
def health():
    """Health check endpoint for Docker."""
    try:
        # Try to connect to Headscale server
        response = requests.get(f"{HEADSCALE_URL}/api/v1/apikey", timeout=5)
        is_headscale_healthy = response.status_code != 500
    except:
        is_headscale_healthy = False

    status = 200 if is_headscale_healthy else 500
    return jsonify({
        'status': 'healthy' if is_headscale_healthy else 'unhealthy',
        'headscale_connection': is_headscale_healthy
    }), status

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)