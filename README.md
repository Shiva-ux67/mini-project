# WhistleSecure - Secure Evidence Submission Platform

A comprehensive web application for secure evidence submission and management with end-to-end encryption using Feistel cipher.

## Features

- **Secure Encryption**: Feistel cipher (4-round) encryption for all submissions
- **Role-Based Access Control**: Admin, Seller, and Customer roles with distinct dashboards
- **Audit Logging**: Complete audit trail of all user actions
- **User Management**: Admin controls for managing users and permissions
- **Message Encryption/Decryption**: Secure handling of evidence submissions

## Project Structure

```
WhistleSecure_Project/
├── app.py                 # Main Flask application
├── crypto_utils.py        # Encryption/decryption utilities
├── requirements.txt       # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css     # Global application styles
│   └── js/
│       └── script.js     # Client-side functionality
├── templates/
│   ├── index.html        # Landing page
│   ├── login.html        # Login page
│   ├── signup.html       # Registration page
│   ├── admin/            # Admin dashboard pages
│   │   ├── dashboard.html
│   │   ├── audit.html
│   │   ├── users.html
│   │   ├── keys.html
│   │   └── settings.html
│   ├── seller/           # Seller dashboard pages
│   │   ├── dashboard.html
│   │   ├── upload.html
│   │   ├── files.html
│   │   ├── message.html
│   │   └── products.html
│   └── customer/         # Customer dashboard pages
│       ├── dashboard.html
│       ├── files.html
│       ├── message.html
│       ├── decrypt.html
│       └── products.html
└── database/
    └── db.json          # TinyDB database file

```

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Steps

1. **Clone/Navigate to the project directory**
```bash
cd WhistleSecure_Project
```

2. **Create a virtual environment (optional but recommended)**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

## Running the Application

1. **Start the Flask development server**
```bash
python app.py
```

2. **Open your browser and navigate to**
```
http://localhost:5000
```

## User Roles & Access

### Admin
- View all users and submissions
- Access audit logs
- Manage encryption keys
- Configure system settings
- Dashboard: `/admin/dashboard`

### Seller
- Submit encrypted evidence
- View own submissions
- Manage products
- Access message logs
- Dashboard: `/seller/dashboard`

### Customer
- View all encrypted submissions
- Decrypt messages with proper key
- Browse evidence repository
- Access message logs
- Dashboard: `/customer/dashboard`

## Default System Key

The default encryption key for Feistel cipher:
```
FEISTEL_KEY_2026
```

**Note**: Change this in production for enhanced security.

## Encryption Mechanism

The application uses a **Feistel Cipher** with the following properties:
- **Algorithm**: 4-round Feistel Network
- **Hash Function**: SHA-256
- **Output Format**: Hexadecimal string storage
- **Key Management**: Single system key for encryption/decryption

### Example Encryption Flow
1. User submits plaintext evidence
2. System applies 4-round Feistel encryption
3. Result stored as hexadecimal string in database
4. Only authorized users with correct key can decrypt

## Database

The application uses **TinyDB**, a lightweight JSON-based database:
- Location: `database/db.json`
- Tables:
  - `users`: User accounts and credentials
  - `messages`: Encrypted submissions
  - `audit_logs`: System activity logs

## API Endpoints

### Public Routes
- `GET /` - Landing page
- `GET /login` - Login page
- `POST /login` - Process login
- `GET /signup` - Registration page
- `POST /signup` - Create new account
- `GET /logout` - Logout user

### Admin Routes
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/audit` - View audit logs
- `GET /admin/users` - Manage users
- `GET /admin/keys` - Key management
- `GET /admin/settings` - System settings

### Seller Routes
- `GET /seller/dashboard` - Seller workspace
- `GET /seller/upload` - Submission form
- `POST /seller/upload` - Submit encrypted evidence
- `GET /seller/files` - View own submissions
- `GET /seller/messages` - Message logs
- `GET /seller/products` - Product catalog

### Customer Routes
- `GET /customer/dashboard` - Customer workspace
- `GET /customer/files` - Evidence repository
- `GET /customer/messages` - Message logs
- `GET /customer/decrypt/<msg_id>` - Decrypt specific message
- `POST /customer/decrypt/<msg_id>` - Process decryption
- `GET /customer/products` - Browse products

## Security Features

1. **Password Hashing**: PBKDF2-SHA256 for password storage
2. **Session Management**: Flask secure session cookies
3. **Role-Based Access Control**: Protected routes based on user role
4. **Audit Logging**: All critical actions logged with timestamp
5. **End-to-End Encryption**: Feistel cipher for data protection

## File Management

### Static Files
- CSS files in `static/css/` for styling
- JavaScript files in `static/js/` for client-side functionality

### Template Files
- HTML templates using Jinja2 templating engine
- Role-specific layouts for different user types
- Responsive design for mobile compatibility

## Development

### Code Structure
- **app.py**: Flask application with all route handlers
- **crypto_utils.py**: Encryption/decryption utilities
- **Templates**: Jinja2 HTML templates for dynamic content
- **Static Files**: CSS, JavaScript for frontend

### Key Functions

#### Encryption
```python
feistel_encrypt(plaintext, key, rounds=4)
```
Encrypts plaintext using Feistel cipher

#### Decryption
```python
feistel_decrypt(hex_ciphertext, key, rounds=4)
```
Decrypts encrypted data with provided key

## Troubleshooting

### Port Already in Use
If port 5000 is already in use:
```bash
python app.py --port 5001
```

### Database Issues
If database is corrupted, delete `database/db.json` and restart the application.

### Missing Dependencies
Reinstall all dependencies:
```bash
pip install -r requirements.txt --force-reinstall
```

## Testing Users

For testing purposes, you can create accounts with the following roles:
- **Username**: Demo001, **Password**: password123, **Role**: Admin
- **Username**: Seller001, **Password**: password123, **Role**: Seller
- **Username**: Customer001, **Password**: password123, **Role**: Customer

## Production Deployment

### Important Steps for Production
1. Set `app.debug = False` in app.py
2. Use a production WSGI server (Gunicorn, uWSGI)
3. Use environment variables for sensitive configuration
4. Change the default encryption key
5. Use HTTPS only
6. Implement proper backup strategy for database

### Example Production Run
```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## Contributing

When making changes:
1. Ensure templates include proper CSS/JS links
2. Maintain role-based access control
3. Log all critical operations
4. Test with all three user roles

## License

This project is for educational purposes.

## Support

For issues or questions, please refer to the template files and code comments for detailed explanations.

---

**Last Updated**: February 2026
**Version**: 1.0.0
