# Secure File Upload System

A robust, secure, and user-friendly file upload system with chunk-based uploads, user management, and sharing capabilities.

## Features

### Core Features
- **Chunk-Based Uploads**: Support for large file uploads with automatic chunking and resumable uploads
- **User Management**: Secure user registration and authentication system
- **File Management**: Upload, download, rename, and delete files
- **Sharing System**: Create password-protected shareable links with expiration
- **Admin Dashboard**: Manage users, monitor storage usage, and extend sessions

### Security Features
- JWT-based authentication
- Password hashing with bcrypt
- Rate limiting for registration
- CAPTCHA protection
- Secure file storage with user isolation
- Password-protected share links

### Technical Features
- Express.js backend with RESTful API
- React frontend with modern UI
- Chunk-based upload with progress tracking
- Automatic file type detection
- Bulk download as ZIP
- File metadata tracking
- Audit logging system

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Modern web browser

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-file-upload.git
cd secure-file-upload
```

2. Install backend dependencies:
```bash
cd backend
npm install
```

3. Install frontend dependencies:
```bash
cd ../frontend
npm install
```

4. Create environment files:

Backend (.env):
```
PORT=5000
JWT_SECRET=your_jwt_secret
UPLOAD_DIR=uploads
ADMIN_USERNAME=admin
```
Frontend (.env):
```
REACT_APP_API_URL=http://localhost:5000
```
## Running the Application

1. Start the backend server:
```bash
cd backend
npm start
```

2. Start the frontend development server:
```bash
cd frontend
npm start
```

The application will be available at `http://localhost:3000`

## API Documentation

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - User login
- `GET /auth/profile` - Get user profile
- `PUT /auth/profile/email` - Update email
- `PUT /auth/profile/password` - Update password

### File Management
- `POST /upload` - Upload single file
- `POST /upload/chunk` - Upload file chunk
- `GET /upload/chunks` - Get uploaded chunks
- `GET /upload/status` - Get upload status
- `GET /files` - List user's files
- `GET /files/:filename` - Download file
- `DELETE /files/:filename` - Delete file
- `PUT /files/:filename/rename` - Rename file
- `POST /files/zip` - Bulk download as ZIP

### Sharing
- `POST /files/share` - Create shareable link
- `GET /share/:token` - Access shared file

### Admin Routes
- `GET /admin/users` - List all users
- `DELETE /admin/users/:username` - Delete user
- `PUT /admin/users/:username/session` - Extend user session
- `DELETE /admin/cleanup` - Clean up expired users

## Security Considerations

- All passwords are hashed using bcrypt
- JWT tokens are used for authentication
- Rate limiting is implemented for registration
- CAPTCHA protection for registration
- User files are isolated in separate directories
- Share links can be password-protected and time-limited

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Express.js](https://expressjs.com/)
- [React](https://reactjs.org/)
- [Multer](https://github.com/expressjs/multer)
- [JWT](https://jwt.io/)
- [Bcrypt](https://github.com/dcodeIO/bcrypt.js)
