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
from datetime import timedelta

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
    if response.status_code == 401:  # Unauthorized - key expired or invalid
        session.pop('api_key', None)
        raise requests.exceptions.RequestException("Session expired. Please login again.")
    response.raise_for_status()

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
        response = requests.delete(url, headers=headers, timeout=5)
        handle_api_response(response)
        return response.json(), None
    except requests.exceptions.RequestException as e:
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
    # Don't allow deletion of the current key
    if session.get('api_key_id') == key_id:
        flash("Cannot delete the API key that you're currently using", 'warning')
        return redirect(url_for('apikeys'))

    try:
        # First check if the key exists
        check_response = requests.get(
            f"{HEADSCALE_URL}/api/v1/apikey/{key_id}", 
            headers={"Authorization": f"Bearer {session['api_key']}"}, 
            timeout=5
        )
        
        if check_response.status_code == 404:
            flash("API key not found", 'warning')
            return redirect(url_for('apikeys'))
            
        # Attempt to delete the key
        response = requests.delete(
            f"{HEADSCALE_URL}/api/v1/apikey/{key_id}", 
            headers={"Authorization": f"Bearer {session['api_key']}"}, 
            timeout=5
        )
        
        if response.status_code == 200:
            flash("API Key deleted successfully", 'success')
        elif response.status_code == 403:
            flash("You don't have permission to delete this API key", 'danger')
        elif response.status_code == 401:
            session.pop('api_key', None)
            flash('Your session has expired. Please login again.', 'warning')
            return redirect(url_for('login'))
        else:
            flash(f"Error deleting API key: {response.status_code} - {response.text}", 'danger')
            
    except requests.exceptions.RequestException as e:
        flash(f"Error connecting to Headscale server: {str(e)}", 'danger')
    
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
                    session['api_key_id'] = current_key['id']
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