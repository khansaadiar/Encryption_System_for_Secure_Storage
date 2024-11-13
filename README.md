# Encryption_System_for_Secure_Storage
This project is a secure cloud storage system designed to protect user documents using AES and DES encryption algorithms. The system includes features for user and admin logins, ensuring role-based access while securely managing and storing encryption keys.

## Features
- **AES and DES Encryption:** Documents are encrypted using AES or DES, adding a strong layer of security for sensitive data.
- **User and Admin Authentication:**
    - **User Login:** Users can securely upload and manage their encrypted files.
    - **Admin Login:** Admins can access a dashboard that shows file statuses but restricts file previews to maintain encryption security.
- **Secure Key Storage:** Encrypted keys are stored in a secure database, and only authorized admins can access them after login.
- **Role-Based Access Control:** Differentiated functionality for users and admins ensures secure and limited access based on roles.
- **No Preview for Admins:** The admin dashboard explicitly indicates that files are encrypted, disabling preview functionality.

## Technologies Used

- **Python** for core application logic
- **AES and DES Encryption** (PyCryptodome library) for file encryption and decryption

## Usage
### 1. Run the application:
``python main.py``
### 2. User Functions:
- **Register/Login:** Users can register or log in to their account.
- **Upload Files:** Users can upload files, which are then encrypted and stored securely.
- **Manage Files:** Users can view their uploaded files (encrypted) and manage them.
### 3. Admin Functions:
- **Admin Login:** Admins can log in to access the dashboard.
- **View Encrypted Files:** Admins can view a list of encrypted files with a message that preview is not allowed.
- **Access Keys:** Admins can retrieve encryption keys for specific files after logging in.