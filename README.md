# SecureLock Password Manager

SecureLock is a secure password manager built using Flask and JavaScript that allows users to store, manage, and organize credentials in an encrypted vault.

## Live Demo
https://your-render-app.onrender.com

## Features

* User authentication with master password
* Secure encrypted vault storage
* Add, edit, delete, and search credentials
* Password strength analysis using zxcvbn
* Built-in password generator
* Session-based authentication
* Category-based credential organization
* Responsive dark-themed UI
* Matrix-inspired security interface effects

## Tech Stack

### Frontend

* HTML5
* CSS3
* JavaScript
* Tailwind CSS

### Backend

* Python
* Flask
* Flask-CORS

### Security

* PBKDF2-HMAC key derivation
* Session-based authentication
* Encrypted vault storage

## Project Structure

```text
securelock/
│
├── app.py
├── requirements.txt
├── vault.json
│
├── static/
│   ├── login.html
│   ├── vault.html
│
└── README.md
```

## Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/securelock.git
cd securelock
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/Mac:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Screenshots

1. Login Page
  <img width="1915" height="862" alt="image" src="https://github.com/user-attachments/assets/b09875a8-26cf-4dc7-8b32-e5284bc56383" />

3. Vault Dashboard
  <img width="1905" height="870" alt="image" src="https://github.com/user-attachments/assets/e45e5f10-9312-4d08-ac72-5c23f77037c0" />

5. Password Generator
   <img width="1897" height="846" alt="image" src="https://github.com/user-attachments/assets/a138f8c9-febc-4996-a727-ec47d3c55012" />

7. Credential Management
<img width="1208" height="802" alt="image" src="https://github.com/user-attachments/assets/c098fce9-2cde-4df8-bc80-a93375d7458f" />

## Future Improvements

* PostgreSQL database integration
* Two-factor authentication (2FA)
* Password breach detection
* Secure password sharing
* Cloud synchronization
* Browser extension support

## Author

Kunal Kapoor

MIT Manipal – B.Tech Information Technology
