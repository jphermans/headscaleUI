# Headscale UI

🚀 **Headscale UI** is a sleek and modern web interface for managing Headscale users and nodes.  
Built with **Flask** and **Bootstrap**, this UI provides an intuitive way to interact with your Headscale instance.

---

## 🌟 Features
- 📌 **Manage Users**: Add, edit, and remove Headscale users.
- 🖥️ **Manage Nodes**: View, assign, and delete nodes.
- 🎨 **Modern UI**: Built with Bootstrap for a clean and responsive design.
- 🌐 **Runs Anywhere**: Can be deployed on any server, separate from Headscale.
- 🔐 **Secure API key-based authentication**
- 🔑 **API key management**
- 🔒 **Session management with auto-logout**
- 🌓 **Theme Support**: Light, Dark, and System theme options
- 🔔 **Auto-dismissing notifications**

---

## 📦 Installation

### 🔹 Prerequisites
Ensure you have the following installed:
- Python 3.9+
- Flask
- Docker & Docker Compose (for Headscale)

### 🔹 Install Dependencies
Clone the repository and install required packages:

```bash
git clone https://github.com/jphsystems/headscale-ui.git
cd headscale-ui
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 🔹 Set up the `.env` file
Create a `.env` file in the project directory and configure your Headscale instance:

```env
HEADSCALE_URL=https://headscale.example.com
SECRET_KEY=your_secret_key_here
```

---

## 🚀 Running the Application

1. Start the Flask application:
```bash
python app.py
```

2. Visit **[`http://localhost:5001`](http://localhost:5001)** in your browser.

---

## 🔐 Authentication

### Creating a Login Key

1. Access your Headscale server terminal
2. Run the command:
   ```bash
   headscale apikey create --expiration 8760h
   ```
3. Copy the generated key - you'll need it to log in to HeadscaleUI

### Validity Periods

When creating an API key, you can specify different validity periods:
- 24h = 1 day
- 168h = 7 days
- 720h = 30 days
- 8760h = 1 year (recommended)
- 87600h = 10 years

### Security Notes

- Store your API key securely - it provides full access to your Headscale server
- Sessions remain active for 12 hours
- Automatic logout when API key expires
- Create a new key if you suspect your current one is compromised

---

## 📜 API Endpoints

| Endpoint           | Method | Description |
|-------------------|--------|-------------|
| `/users`          | GET/POST | View and manage users |
| `/nodes`          | GET/POST | View and assign nodes |
| `/apikeys`        | GET/POST | Manage API keys |
| `/help`           | GET      | View documentation |

---

## 🔥 Contributing
Feel free to submit **issues and pull requests** to improve the project.

---

## 📄 License
This project is licensed under the **MIT License**.

---

### 👨‍💻 Developed by **Jean-Pierre**
