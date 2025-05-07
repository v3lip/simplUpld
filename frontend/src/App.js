import React, { useState, useEffect } from 'react';
import axios from 'axios';
import Header from './components/Header';
import './App.css';

// Configure base URL and auth header from stored token
axios.defaults.baseURL = process.env.REACT_APP_API_URL || `${window.location.protocol}//${window.location.hostname}:5000`;
const initialToken = localStorage.getItem('token');
if (initialToken) {
  axios.defaults.headers.common['Authorization'] = `Bearer ${initialToken}`;
}

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [captchaId, setCaptchaId] = useState(null);
  // Admin dashboard state
  const [adminModalOpen, setAdminModalOpen] = useState(false);
  const [adminUsers, setAdminUsers] = useState([]);
  const [captchaQuestion, setCaptchaQuestion] = useState('');
  const [captchaAnswer, setCaptchaAnswer] = useState('');
  const [user, setUser] = useState(() => localStorage.getItem('user'));
  const [selectedFile, setSelectedFile] = useState(null);
  const [files, setFiles] = useState([]);
  const [timeLeft, setTimeLeft] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(null);
  const [durationMs, setDurationMs] = useState(3600000);
  // Show register page flag
  const [showRegister, setShowRegister] = useState(false);
  // Search and sort state for file explorer
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState(null);
  const [sortOrder, setSortOrder] = useState('asc');
  const [isDragOver, setIsDragOver] = useState(false);
  // Sort handler toggles order or sets new field
  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder('asc');
    }
  };

  // Helper to format file sizes into KB/MB/GB
  const formatSize = (bytes) => {
    if (bytes < 5 * 1024 * 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    } else if (bytes < 2 * 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    } else {
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    }
  };

  // Fetch files function
  const fetchFiles = async () => {
    try {
      const params = {};
      if (searchTerm) params.search = searchTerm;
      if (sortBy) { params.sortBy = sortBy; params.order = sortOrder; }
      
      console.log('Fetching files with params:', params);
      const res = await axios.get('/files', { 
        params,
        validateStatus: function (status) {
          return status < 500; // Resolve only if the status code is less than 500
        }
      });
      
      if (res.status === 200) {
        console.log('Files fetched successfully:', res.data);
        setFiles(res.data);
      } else {
        console.error('Error response from server:', res.data);
        setFiles([]);
        if (res.data && res.data.error) {
          alert(`Error loading files: ${res.data.error}`);
        } else {
          alert('Error loading files. Please try again.');
        }
      }
    } catch (err) {
      console.error('Error fetching files:', err);
      console.error('Error details:', {
        message: err.message,
        response: err.response?.data,
        status: err.response?.status
      });
      setFiles([]);
      alert('Failed to load files. Please check your connection and try again.');
    }
  };

  // Fetch files and session on user change, and start countdown
  useEffect(() => {
    let interval;
    if (user) {
      // load files
      fetchFiles();
      // load session timer
      (async () => {
        try {
          const res = await axios.get('/auth/session');
          setTimeLeft(res.data.timeLeft);
        } catch (err) {
          console.error('Error fetching session', err);
        }
      })();
      // start countdown
      interval = setInterval(() => {
        setTimeLeft(prev => {
          if (prev <= 1000) {
            clearInterval(interval);
            handleLogout();
            return 0;
          }
          return prev - 1000;
        });
      }, 1000);
    } else {
      setTimeLeft(null);
    }
    return () => clearInterval(interval);
  }, [user]);

  // Re-fetch files when search or sorting changes
  useEffect(() => { if (user) fetchFiles(); }, [searchTerm, sortBy, sortOrder]);

  // Fetch a new captcha when the register/login form loads
  const getCaptcha = async () => {
    console.log('Fetching captcha from', process.env.REACT_APP_API_URL);
    try {
      const endpoint = `${process.env.REACT_APP_API_URL}/auth/captcha`;
      console.log('GET', endpoint);
      const res = await axios.get(endpoint);
      setCaptchaId(res.data.captchaId);
      setCaptchaQuestion(res.data.question);
      setCaptchaAnswer('');
    } catch (err) {
      console.error('Error fetching captcha', err);
      setCaptchaQuestion('Failed to load captcha');
    }
  };

  // Fetch captcha whenever we enter the Register view
  useEffect(() => {
    if (showRegister) getCaptcha();
  }, [showRegister]);

  // Format milliseconds to hh:mm:ss or mm:ss
  const formatTime = ms => {
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    const hh = hours.toString();
    const mm = minutes.toString().padStart(2, '0');
    const ss = seconds.toString().padStart(2, '0');
    return hours > 0
      ? `${hh}:${mm}:${ss}`      // show hours when at least 1 hour
      : `${mm}:${ss}`;            // otherwise show mm:ss
  };

  // Registration
  const handleRegister = async () => {
    if (username.trim() && password.trim() && captchaAnswer.trim()) {
      try {
        await axios.post('/auth/register', {
          username: username.trim(),
          password: password.trim(),
          captchaId,
          captchaAnswer: captchaAnswer.trim(),
          durationMs
        });
        await handleLogin();
      } catch (err) {
        console.error('Error registering user', err.response?.data || err);
        alert(err.response?.data?.error || 'Registration failed');
        // refresh captcha on failure
        getCaptcha();
      }
    } else {
      alert('Please fill all fields and captcha');
    }
  };

  // Login
  const handleLogin = async () => {
    if (username.trim() && password.trim()) {
      try {
        const res = await axios.post('/auth/login', { username: username.trim(), password: password.trim() });
        const token = res.data.token;
        localStorage.setItem('token', token);
        localStorage.setItem('user', username.trim());
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        setUser(username.trim());
        setPassword('');
      } catch (err) {
        console.error('Error logging in', err);
      }
    }
  };

  // Logout
  const handleLogout = () => {
    localStorage.removeItem('user');
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    setFiles([]);
    // Reset captcha on logout
    setCaptchaId(null);
    setCaptchaQuestion('');
    setCaptchaAnswer('');
  };

  const handleFileChange = (e) => setSelectedFile(e.target.files[0]);

  const handleDragOver = (e) => { e.preventDefault(); setIsDragOver(true); };
  const handleDragLeave = (e) => { e.preventDefault(); setIsDragOver(false); };
  const handleDrop = (e) => { e.preventDefault(); setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setSelectedFile(e.dataTransfer.files[0]);
      e.dataTransfer.clearData();
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    const threshold = 5 * 1024 * 1024; // 5MB
    setUploadProgress(0);
    if (selectedFile.size <= threshold) {
      // Standard upload for small files
      const formData = new FormData();
      formData.append('file', selectedFile);
      try {
        await axios.post('/upload', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
          onUploadProgress: (event) => {
            const percent = Math.round((event.loaded * 100) / event.total);
            setUploadProgress(percent);
          }
        });
        fetchFiles();
      } catch (err) {
        console.error('Error uploading file', err);
        alert('Failed to upload file. Please try again.');
      } finally {
        setSelectedFile(null);
        setTimeout(() => setUploadProgress(null), 500);
      }
    } else {
      // Chunked upload for large files
      const chunkSize = 1 * 1024 * 1024; // 1MB
      const totalChunks = Math.ceil(selectedFile.size / chunkSize);
      const fileName = selectedFile.name;
      let uploadSuccess = true;
      let uploadedChunks = new Set();
      
      try {
        // Check for existing chunks
        try {
          const { data } = await axios.get('/upload/chunks', {
            params: { fileName }
          });
          uploadedChunks = new Set(data.uploadedChunks || []);
        } catch (err) {
          console.warn('Could not check for existing chunks, starting fresh upload');
          uploadedChunks = new Set();
        }
        
        // Calculate initial progress based on existing chunks
        if (uploadedChunks.size > 0) {
          const initialProgress = Math.round((uploadedChunks.size / totalChunks) * 85);
          setUploadProgress(initialProgress);
        }
        
        // Upload remaining chunks
        for (let index = 0; index < totalChunks; index++) {
          // Skip if chunk already exists
          if (uploadedChunks.has(index)) {
            continue;
          }
          
          const start = index * chunkSize;
          const end = Math.min(start + chunkSize, selectedFile.size);
          const chunk = selectedFile.slice(start, end);
          
          const response = await axios.post('/upload/chunk', chunk, {
            params: { fileName, chunkIndex: index, totalChunks },
            headers: { 'Content-Type': 'application/octet-stream' }
          });
          
          // Update uploaded chunks from response
          if (response.data.uploadedChunks) {
            uploadedChunks = new Set(response.data.uploadedChunks);
          }
          
          // Update progress based on response status
          if (response.data.status === 'queued_for_merge') {
            setUploadProgress(90); // Show 90% when queued for merge
            
            // Poll merge status
            const pollMergeStatus = async () => {
              try {
                const statusRes = await axios.get('/upload/merge-status', {
                  params: { fileName }
                });
                
                if (statusRes.data.status === 'completed') {
                  setUploadProgress(100);
                  await fetchFiles();
                  return true;
                } else if (statusRes.data.status === 'merging') {
                  setUploadProgress(95);
                  return false;
                } else if (statusRes.data.status === 'not_found') {
                  throw new Error('Merge failed - file not found');
                }
                return false;
              } catch (error) {
                console.error('Error checking merge status:', error);
                throw error;
              }
            };

            // Poll every 2 seconds until complete or error
            while (!(await pollMergeStatus())) {
              await new Promise(resolve => setTimeout(resolve, 2000));
            }
          } else {
            // Calculate progress based on actual uploaded chunks
            setUploadProgress(Math.round((uploadedChunks.size / totalChunks) * 85));
          }
        }
      } catch (err) {
        console.error('Error uploading chunks:', err);
        alert('Failed to upload file. Please try again.');
        uploadSuccess = false;
      } finally {
        setSelectedFile(null);
        if (uploadSuccess) {
          setTimeout(() => setUploadProgress(null), 1000);
        } else {
          setUploadProgress(null);
        }
      }
    }
  };

  // Download handler (direct link to avoid CORS/XHR issues)
  const handleDownload = (fileName) => {
    // Strip timestamp prefix for download filename
    const dashIndex = fileName.indexOf('-');
    const originalName = dashIndex !== -1 ? fileName.slice(dashIndex + 1) : fileName;
    const token = localStorage.getItem('token');
    const downloadUrl = `${process.env.REACT_APP_API_URL}/files/${fileName}?token=${encodeURIComponent(token)}&download=true`;
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.setAttribute('download', originalName);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  // Delete handler
  const handleDelete = async (fileName) => {
    if (!window.confirm('Are you sure you want to delete this file?')) return;
    try {
      await axios.delete(`/files/${fileName}`);
      fetchFiles();
    } catch (err) {
      console.error('Error deleting file', err);
      alert(err.response?.data?.error || 'Delete failed');
    }
  };

  // Share modal state and handlers
  const [shareModalOpen, setShareModalOpen] = useState(false);
  const [shareModalFile, setShareModalFile] = useState('');
  const [shareExpiryHours, setShareExpiryHours] = useState(24);
  const [sharePasswordInput, setSharePasswordInput] = useState('');
  const [shareLinkResult, setShareLinkResult] = useState('');
  const [shareError, setShareError] = useState(null);
  // Rename modal state and handlers
  const [renameModalOpen, setRenameModalOpen] = useState(false);
  const [renameFileName, setRenameFileName] = useState('');
  const [renameOriginalName, setRenameOriginalName] = useState('');
  const [renameInput, setRenameInput] = useState('');
  const [renameError, setRenameError] = useState(null);

  const openShareModal = (fileName) => {
    setShareModalFile(fileName);
    // Initialize expiry slider to user's remaining session hours
    setShareExpiryHours(maxExpiryHours);
    setSharePasswordInput('');
    setShareLinkResult('');
    setShareError(null);
    setShareModalOpen(true);
  };

  const submitShare = async () => {
    try {
      const res = await axios.post('/files/share', { fileName: shareModalFile, expiresIn: shareExpiryHours * 3600, password: sharePasswordInput || undefined });
      setShareLinkResult(res.data.shareLink);
    } catch (err) {
      setShareError(err.response?.data?.error || 'Share failed');
    }
  };

  const closeShareModal = () => setShareModalOpen(false);

  const openRenameModal = (fileName, originalName) => {
    setRenameFileName(fileName);
    setRenameOriginalName(originalName);
    setRenameInput(originalName);
    setRenameError(null);
    setRenameModalOpen(true);
  };

  const submitRename = async () => {
    if (!renameInput.trim()) {
      setRenameError('Name cannot be empty');
      return;
    }
    try {
      await axios.put(`/files/${renameFileName}/rename`, { newName: renameInput.trim() });
      setRenameModalOpen(false);
      fetchFiles();
    } catch (err) {
      setRenameError(err.response?.data?.error || 'Rename failed');
    }
  };

  const closeRenameModal = () => setRenameModalOpen(false);

  // Compute maximum share expiry hours based on session timer
  const maxExpiryHours = timeLeft !== null ? Math.max(1, Math.floor(timeLeft / (1000 * 3600))) : 24;

  // Bulk selection state
  const [selectedFilesMap, setSelectedFilesMap] = useState({});
  const [previewFile, setPreviewFile] = useState(null);
  const selectedList = Object.keys(selectedFilesMap).filter(fn => selectedFilesMap[fn]);
  const allSelected = files.length > 0 && selectedList.length === files.length;
  
  const handleSelectAll = () => {
    if (allSelected) setSelectedFilesMap({});
    else {
      const newMap = {};
      files.forEach(f => { newMap[f.fileName] = true; });
      setSelectedFilesMap(newMap);
    }
  };
  const handleSelectOne = (fileName) => {
    setSelectedFilesMap(prev => {
      const copy = { ...prev };
      if (copy[fileName]) delete copy[fileName];
      else copy[fileName] = true;
      return copy;
    });
  };
  
  // Bulk delete
  const handleBulkDelete = async () => {
    if (!selectedList.length) return;
    if (!window.confirm('Delete selected files?')) return;
    try {
      await Promise.all(selectedList.map(fn => axios.delete(`/files/${fn}`)));
      setSelectedFilesMap({});
      fetchFiles();
    } catch (err) {
      console.error('Bulk delete error', err);
      alert('Failed to delete some files');
    }
  };
  
  // Bulk download as ZIP
  const handleBulkDownload = () => {
    if (!selectedList.length) return;
    const token = localStorage.getItem('token');
    // Build query string: files=file1&files=file2...
    const fileParams = selectedList.map(f => `files=${encodeURIComponent(f)}`).join('&');
    const url = `${process.env.REACT_APP_API_URL}/files/zip?token=${encodeURIComponent(token)}&${fileParams}`;
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'files.zip');
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  // Handler to open preview modal
  const handlePreview = (file) => {
    setPreviewFile(file);
  };

  // Dropdown menu state for file actions
  const [openDropdown, setOpenDropdown] = useState(null);
  const toggleDropdown = (fileName) => { setOpenDropdown(prev => prev === fileName ? null : fileName); };

  // Close dropdown when clicking outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (!e.target.closest('.dropdown')) {
        setOpenDropdown(null);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, []);

  // Settings modal state
  const [settingsModalOpen, setSettingsModalOpen] = useState(false);
  const [profile, setProfile] = useState({ username: '', email: '', timeLeft: 0, storageUsed: 0, isAdmin: false });
  const [currentPwInput, setCurrentPwInput] = useState('');
  const [newPwInput, setNewPwInput] = useState('');
  const [sessionLengthInput, setSessionLengthInput] = useState(1);
  const [saveMessage, setSaveMessage] = useState('');
  const [settingsError, setSettingsError] = useState('');
  const [toastMessage, setToastMessage] = useState('');

  // Activity log modal state
  const [activityModalOpen, setActivityModalOpen] = useState(false);
  const [activityLogs, setActivityLogs] = useState([]);
  const formatDate = ts => new Date(ts).toLocaleString();
  const actionLabels = { upload: 'Uploaded', download: 'Downloaded', delete: 'Deleted' };

  // Fetch profile
  useEffect(() => {
    if (user) {
      axios.get('/auth/profile').then(res => {
        setProfile(res.data);
        setSessionLengthInput(Math.max(1, Math.floor(res.data.timeLeft / 3600000)));
      }).catch(console.error);
    }
  }, [user, shareLinkResult, shareModalOpen]);

  // Clear toast message after showing
  useEffect(() => {
    if (toastMessage) {
      const timer = setTimeout(() => setToastMessage(''), 3000);
      return () => clearTimeout(timer);
    }
  }, [toastMessage]);

  const openSettingsModal = () => {
    setSaveMessage('');
    setSettingsError('');
    setSettingsModalOpen(true);
  };
  const closeSettingsModal = () => setSettingsModalOpen(false);

  const savePassword = async () => {
    try { await axios.put('/auth/profile/password', { currentPassword: currentPwInput, newPassword: newPwInput }); setSaveMessage('Password changed'); }
    catch (err) { setSettingsError(err.response?.data?.error || 'Change failed'); }
  };
  const saveSession = async () => {
    try {
      const res = await axios.put('/auth/session', { durationMs: sessionLengthInput * 3600000 });
      setProfile(p => ({ ...p, timeLeft: res.data.timeLeft }));
      setTimeLeft(res.data.timeLeft);
      setToastMessage(`Session extended by ${sessionLengthInput}h`);
    } catch (err) {
      setSettingsError(err.response?.data?.error || 'Extend failed');
    }
  };

  // Open Activity Log modal and fetch logs
  const openActivityModal = async () => {
    try {
      const res = await axios.get('/auth/logs');
      setActivityLogs(res.data.logs.reverse());
    } catch (err) {
      console.error('Failed to load activity logs', err);
      setActivityLogs([]);
    }
    setActivityModalOpen(true);
  };
  const closeActivityModal = () => setActivityModalOpen(false);

  // Open Admin modal and fetch users
  const openAdminModal = async () => {
    try {
      const res = await axios.get('/admin/users');
      setAdminUsers(res.data.users);
    } catch (err) {
      console.error('Failed to fetch admin users', err);
      setAdminUsers([]);
    }
    setAdminModalOpen(true);
  };
  const closeAdminModal = () => setAdminModalOpen(false);

  // Delete a user account
  const handleDeleteUser = async (username) => {
    if (!window.confirm(`Delete user '${username}'? This will remove their files and account.`)) return;
    try {
      await axios.delete(`/admin/users/${encodeURIComponent(username)}`);
      // refresh list
      const res = await axios.get('/admin/users');
      setAdminUsers(res.data.users);
    } catch (err) {
      console.error('Failed to delete user', err);
      alert(err.response?.data?.error || 'Delete failed');
    }
  };
  // Reset session for a user
  const handleResetUserSession = async (username) => {
    const hours = window.prompt(`Enter hours to extend session for '${username}':`, '1');
    if (!hours) return;
    const h = Number(hours);
    if (isNaN(h) || h <= 0) { alert('Invalid hours'); return; }
    try {
      await axios.put(`/admin/users/${encodeURIComponent(username)}/session`, { durationMs: h * 3600000 });
      // refresh list
      const res = await axios.get('/admin/users');
      setAdminUsers(res.data.users);
    } catch (err) {
      console.error('Failed to reset session', err);
      alert(err.response?.data?.error || 'Reset failed');
    }
  };

  // Admin dashboard filter and sort
  const [adminFilter, setAdminFilter] = useState('');
  const [adminSortField, setAdminSortField] = useState('username');
  const [adminSortOrder, setAdminSortOrder] = useState('asc');
  const handleAdminSort = (field) => {
    if (adminSortField === field) setAdminSortOrder(o => o === 'asc' ? 'desc' : 'asc');
    else { setAdminSortField(field); setAdminSortOrder('asc'); }
  };

  if (!user) {
    return (
      <div className="login-container">
        {showRegister ? (
          <>
            <h2>Register</h2>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <select
              value={durationMs}
              onChange={(e) => setDurationMs(Number(e.target.value))}
            >
              <option value={30000}>30 sec</option>
              <option value={1800000}>30 min</option>
              <option value={3600000}>60 min</option>
              <option value={10800000}>3 hrs</option>
              <option value={21600000}>6 hrs</option>
              <option value={43200000}>12 hrs</option>
              <option value={86400000}>24 hrs</option>
            </select>
            {/* Captcha question and answer field */}
            <p className="captcha-question">{captchaQuestion || 'Loading captcha...'}</p>
            <input
              type="text"
              placeholder="Captcha Answer"
              value={captchaAnswer}
              onChange={(e) => setCaptchaAnswer(e.target.value)}
            />
            <div className="login-actions">
              <button className="register-button" onClick={handleRegister}>Register</button>
              <button className="login-button" onClick={() => setShowRegister(false)}>Back to Login</button>
            </div>
          </>
        ) : (
          <>
            <h2>Login</h2>
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <div className="login-actions">
              <button className="login-button" onClick={handleLogin}>Login</button>
              <button className="register-button" onClick={() => setShowRegister(true)}>Register</button>
            </div>
          </>
        )}
      </div>
    );
  }

  return (
    <div className={`App${openDropdown ? ' dropdown-open' : ''}`}>
      {timeLeft !== null && !profile.isAdmin && (
        <div className="session-timer">
          Session expires in: {formatTime(timeLeft)}
        </div>
      )}
      <Header
        user={user}
        onLogout={handleLogout}
        onSettings={openSettingsModal}
        onActivity={openActivityModal}
        onAdmin={openAdminModal}
        isAdmin={profile.isAdmin}
      />
      {activityModalOpen && (
        <div className="modal-overlay" onClick={closeActivityModal}>
          <div className="modal-content activity-modal" onClick={e => e.stopPropagation()}>
            <h3>Activity Log</h3>
            <div className="modal-body">
              {activityLogs.length ? (
                <table className="activity-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Action</th>
                      <th>File</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activityLogs.map((entry, idx) => (
                      <tr key={idx}>
                        <td className="activity-time">{formatDate(entry.timestamp)}</td>
                        <td className={`activity-action action-${entry.action}`}>{actionLabels[entry.action] || entry.action}</td>
                        <td className="activity-file">{entry.fileName || ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p>No activity available.</p>
              )}
            </div>
            <div className="modal-actions">
              <button onClick={closeActivityModal}>Close</button>
            </div>
          </div>
        </div>
      )}
      <h1>File Upload and Download</h1>
      <div
        className={`upload-section${isDragOver ? ' drag-over' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input id="file-upload" type="file" onChange={handleFileChange} />
        <label htmlFor="file-upload" className="custom-file-upload">
          {selectedFile ? selectedFile.name : 'Drag & drop a file here, or click to select'}
        </label>
        <button onClick={handleUpload}>Upload</button>
        {uploadProgress !== null && (
          <div className="upload-progress">
            <progress value={uploadProgress} max="100" />
            <span>{uploadProgress}%</span>
          </div>
        )}
      </div>
      {/* File search and bulk actions */}
      <div className="file-controls">
        <input
          type="text"
          placeholder="Search files..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <button className="bulk-delete-button" onClick={handleBulkDelete} disabled={!selectedList.length}>
          🗑️ Delete Selected
        </button>
        <button className="bulk-download-button" onClick={handleBulkDownload} disabled={!selectedList.length}>
          📦 Download Selected
        </button>
      </div>
      <h2>Available Files</h2>
      <table className="file-table">
        <thead>
          <tr>
            <th>
              <input type="checkbox" checked={allSelected} onChange={handleSelectAll} />
            </th>
            <th onClick={() => handleSort('dateUploaded')}>
              Date Uploaded {sortBy === 'dateUploaded' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
            </th>
            <th onClick={() => handleSort('name')}>
              Name {sortBy === 'name' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
            </th>
            <th onClick={() => handleSort('type')}>
              Type {sortBy === 'type' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
            </th>
            <th onClick={() => handleSort('size')}>
              Size {sortBy === 'size' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
            </th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {files.map(({ fileName, originalName, dateUploaded, type, size }) => (
            <tr key={fileName}>
              <td>
                <input
                  type="checkbox"
                  checked={!!selectedFilesMap[fileName]}
                  onChange={() => handleSelectOne(fileName)}
                />
              </td>
              <td>{new Date(dateUploaded).toLocaleString()}</td>
              <td onClick={() => handlePreview({ fileName, originalName, type })} style={{ cursor: 'pointer' }}>
                <div className="file-name-cell-content">
                  {['png','jpg','jpeg','gif','webp'].includes(type.toLowerCase()) ? (
                    <img src={`${process.env.REACT_APP_API_URL}/files/${fileName}?token=${encodeURIComponent(localStorage.getItem('token'))}`} alt={originalName} className="thumbnail" />
                  ) : type.toLowerCase() === 'pdf' ? (
                    <span className="pdf-icon">📄</span>
                  ) : type.toLowerCase() === 'mp4' ? (
                    <video className="thumbnail" muted>
                      <source src={`${process.env.REACT_APP_API_URL}/files/${fileName}?token=${encodeURIComponent(localStorage.getItem('token'))}`} type="video/mp4" />
                    </video>
                  ) : null}
                  {originalName}
                </div>
              </td>
              <td>{type}</td>
              <td>{formatSize(size)}</td>
              <td>
                <div className="dropdown">
                  <button className="dropdown-toggle" onClick={() => toggleDropdown(fileName)}>⋮</button>
                  {openDropdown === fileName && (
                    <ul className="dropdown-menu">
                      <li onClick={() => { handleDownload(fileName); setOpenDropdown(null); }}>Download</li>
                      <li onClick={() => { openRenameModal(fileName, originalName); setOpenDropdown(null); }}>Rename</li>
                      <li onClick={() => { openShareModal(fileName); setOpenDropdown(null); }}>Share</li>
                      <li onClick={() => { handleDelete(fileName); setOpenDropdown(null); }}>Delete</li>
                    </ul>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {previewFile && (
        <div className="preview-modal" onClick={() => setPreviewFile(null)}>
          <div className="preview-content" onClick={e => e.stopPropagation()}>
            <button className="close-button" onClick={() => setPreviewFile(null)}>×</button>
            {previewFile.type.toLowerCase() === 'pdf' ? (
              <object data={`${process.env.REACT_APP_API_URL}/files/${previewFile.fileName}?token=${encodeURIComponent(localStorage.getItem('token'))}`} type="application/pdf" width="100%" height="100%">
                <p>Your browser does not support PDFs. <a href={`${process.env.REACT_APP_API_URL}/files/${previewFile.fileName}?token=${encodeURIComponent(localStorage.getItem('token'))}`}>Download PDF</a>.</p>
              </object>
            ) : previewFile.type.toLowerCase() === 'mp4' ? (
              <video controls autoPlay className="preview-video">
                <source src={`${process.env.REACT_APP_API_URL}/files/${previewFile.fileName}?token=${encodeURIComponent(localStorage.getItem('token'))}`} type="video/mp4" />
                Your browser does not support the video tag.
              </video>
            ) : (
              <img src={`${process.env.REACT_APP_API_URL}/files/${previewFile.fileName}?token=${encodeURIComponent(localStorage.getItem('token'))}`} alt={previewFile.originalName} />
            )}
          </div>
        </div>
      )}
      {shareModalOpen && (
        <div className="modal-overlay" onClick={closeShareModal}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <h3>Share "{shareModalFile}"</h3>
            <div className="modal-body">
              <label>
                Expires in:
                <div className="slider-wrapper">
                  <input
                    type="range"
                    min="1"
                    max={maxExpiryHours}
                    value={shareExpiryHours}
                    onChange={e => setShareExpiryHours(Number(e.target.value))}
                  />
                  <span className="slider-value">{shareExpiryHours}h</span>
                </div>
              </label>
              <label>
                Password (optional):
                <input type="text" value={sharePasswordInput} onChange={e => setSharePasswordInput(e.target.value)} />
              </label>
              {shareError && <p className="modal-error">{shareError}</p>}
            </div>
            <div className="modal-actions">
              {!shareLinkResult ? (
                <>
                  <button className="primary-share-button" onClick={submitShare}>Create Link</button>
                  <button className="secondary-share-button" onClick={closeShareModal}>Cancel</button>
                </>
              ) : (
                <>
                  <input type="text" readOnly value={shareLinkResult} onClick={e => e.target.select()} />
                  <button className="primary-share-button" onClick={() => navigator.clipboard.writeText(shareLinkResult)}>Copy</button>
                  <button className="secondary-share-button" onClick={closeShareModal}>Close</button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
      {renameModalOpen && (
        <div className="modal-overlay" onClick={closeRenameModal}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <h3>Rename "{renameOriginalName}"</h3>
            <div className="modal-body">
              <input
                type="text"
                value={renameInput}
                onChange={e => setRenameInput(e.target.value)}
                placeholder="New filename"
              />
              {renameError && <p className="modal-error">{renameError}</p>}
            </div>
            <div className="modal-actions">
              <button className="primary-share-button" onClick={submitRename}>Save</button>
              <button className="secondary-share-button" onClick={closeRenameModal}>Cancel</button>
            </div>
          </div>
        </div>
      )}
      {settingsModalOpen && (
        <div className="modal-overlay" onClick={closeSettingsModal}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            {toastMessage && <div className="modal-success">{toastMessage}</div>}
            <h3>Settings</h3>
            <div className="modal-body">
              <section>
                <h4>Profile</h4>
                <p>Username: {profile.username}</p>
                <p>Storage used: {formatSize(profile.storageUsed)}</p>
                <p>Time left: {formatTime(profile.timeLeft)}</p>
              </section>
              <section>
                <h4>Change Password</h4>
                <input type="password" placeholder="Current Password" value={currentPwInput} onChange={e => setCurrentPwInput(e.target.value)} />
                <input type="password" placeholder="New Password" value={newPwInput} onChange={e => setNewPwInput(e.target.value)} />
                <button onClick={savePassword}>Save Password</button>
              </section>
              {!profile.isAdmin && (
                <section>
                  <h4>Session</h4>
                  <div className="slider-wrapper">
                    <input type="range" min="1" max={24} value={sessionLengthInput} onChange={e => setSessionLengthInput(Number(e.target.value))} />
                    <span>{sessionLengthInput}h</span>
                  </div>
                  <button onClick={saveSession}>Extend Session</button>
                </section>
              )}
              {settingsError && <p className="modal-error">{settingsError}</p>}
            </div>
            <div className="modal-actions">
              <button onClick={closeSettingsModal}>Close</button>
            </div>
          </div>
        </div>
      )}
      {adminModalOpen && (
        <div className="modal-overlay" onClick={closeAdminModal}>
          <div className="modal-content admin-modal" onClick={e => e.stopPropagation()}>
            <h3>Admin Dashboard</h3>
            <div className="modal-body">
              {adminUsers.length ? (
                <>
                  <div className="admin-controls">
                    <input
                      type="text"
                      placeholder="Search users..."
                      value={adminFilter}
                      onChange={e => setAdminFilter(e.target.value)}
                    />
                  </div>
                  <table className="admin-table">
                    <thead>
                      <tr>
                        <th onClick={() => handleAdminSort('username')}>
                          Username {adminSortField==='username'? (adminSortOrder==='asc'?'↑':'↓') : ''}
                        </th>
                        <th onClick={() => handleAdminSort('storageUsed')}>
                          Storage {adminSortField==='storageUsed'? (adminSortOrder==='asc'?'↑':'↓') : ''}
                        </th>
                        <th onClick={() => handleAdminSort('timeLeft')}>
                          Time Left {adminSortField==='timeLeft'? (adminSortOrder==='asc'?'↑':'↓') : ''}
                        </th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {adminUsers
                        .filter(u => u.username.toLowerCase().includes(adminFilter.toLowerCase()))
                        .sort((a, b) => {
                          let diff = 0;
                          if (adminSortField === 'username') diff = a.username.localeCompare(b.username);
                          if (adminSortField === 'storageUsed') diff = a.storageUsed - b.storageUsed;
                          if (adminSortField === 'timeLeft') diff = a.timeLeft - b.timeLeft;
                          return adminSortOrder === 'asc' ? diff : -diff;
                        })
                        .map((u, idx) => (
                          <tr key={idx}>
                            <td>{u.username}</td>
                            <td>{formatSize(u.storageUsed)}</td>
                            <td>{formatTime(u.timeLeft)}</td>
                            <td>
                              <button onClick={() => handleResetUserSession(u.username)}>Reset Session</button>
                              <button onClick={() => handleDeleteUser(u.username)}>Delete</button>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </>
              ) : (
                <p>No users available.</p>
              )}
            </div>
            <div className="modal-actions">
              <button onClick={closeAdminModal}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
