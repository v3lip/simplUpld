require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const archiver = require('archiver');

const app = express();
const PORT = process.env.PORT || 5000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const usersFilePath = path.join(__dirname, 'users.json');
const sharesFilePath = path.join(__dirname, 'shares.json');
const logsFilePath = path.join(__dirname, 'logs.json');

// Rate limiter for registration to prevent account-spam (max 5 per hour)
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Too many accounts created from this IP, please try again after an hour' } });

// Captcha store (id -> answer)
const captchaMap = new Map();

// Schedule removal of captcha after configurable TTL (30 minutes)
function scheduleCaptchaDeletion(id) {
  const ttlMs = 30 * 60 * 1000; // 30 minutes
  setTimeout(() => captchaMap.delete(id), ttlMs);
}

// Endpoint to get a new captcha (CORS enabled)
app.get('/auth/captcha', cors(), (req, res) => {
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const id = crypto.randomUUID();
  captchaMap.set(id, a + b);
  scheduleCaptchaDeletion(id);
  res.json({ captchaId: id, question: `What is ${a} + ${b}?` });
});

// Middleware to authenticate admin users
const authenticateAdmin = (req, res, next) => {
  authenticate(req, res, () => {
    if (req.user !== ADMIN_USERNAME) {
      return res.status(403).json({ error: 'Forbidden: admin only' });
    }
    next();
  });
};

function readUsers() { return JSON.parse(fs.readFileSync(usersFilePath)); }
function writeUsers(users) { fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2)); }

function readShares() {
  if (!fs.existsSync(sharesFilePath)) return [];
  return JSON.parse(fs.readFileSync(sharesFilePath));
}

function writeShares(shares) {
  fs.writeFileSync(sharesFilePath, JSON.stringify(shares, null, 2));
}

function readLogs() {
  if (!fs.existsSync(logsFilePath)) return [];
  return JSON.parse(fs.readFileSync(logsFilePath));
}

function writeLogs(logs) {
  fs.writeFileSync(logsFilePath, JSON.stringify(logs, null, 2));
}

// === Timed deletion setup ===
const deletionTimers = new Map();

// Delete user and their files
function deleteUser(username) {
  const users = readUsers().filter(u => u.username !== username);
  writeUsers(users);
  const userDir = path.join(UPLOAD_DIR, username);
  fs.rmSync(userDir, { recursive: true, force: true });
  // Remove share entries for this user
  const shares = readShares().filter(s => s.user !== username);
  writeShares(shares);
  console.log(`Deleted user ${username} and their files`);
}

// Schedule deletion in ms
function scheduleDeletion(username, delay) {
  // Never delete the admin user
  if (username === ADMIN_USERNAME) return;
  if (deletionTimers.has(username)) clearTimeout(deletionTimers.get(username));
  const timer = setTimeout(() => { deleteUser(username); deletionTimers.delete(username); }, delay);
  deletionTimers.set(username, timer);
}

// On startup, schedule deletions for existing users
readUsers().forEach(u => {
  // Skip admin account
  if (u.username === ADMIN_USERNAME) return;
  if (u.expiresAt) {
    const now = Date.now();
    const msLeft = u.expiresAt - now;
    if (msLeft <= 0) deleteUser(u.username);
    else scheduleDeletion(u.username, msLeft);
  }
});

app.use(cors());
app.use(express.json());

// Register route (with rate limit)
app.post('/auth/register', registerLimiter, async (req, res) => {
  console.log('Register payload:', req.body);
  // Accept a custom duration in milliseconds
  const { username, password, captchaId, captchaAnswer, durationMs } = req.body;
  // Validate captcha
  if (!captchaId || captchaAnswer === undefined) {
    return res.status(400).json({ error: 'Captcha answer required' });
  }
  const correct = captchaMap.get(captchaId);
  if (correct === undefined) {
    return res.status(400).json({ error: 'Invalid captcha' });
  }
  if (correct !== Number(captchaAnswer)) {
    return res.status(400).json({ error: 'Wrong captcha answer' });
  }
  // Remove used captcha
  captchaMap.delete(captchaId);
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const users = readUsers();
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'User already exists' });
  // Validate custom duration
  const ms = Number(durationMs);
  if (!durationMs || isNaN(ms) || ms <= 0) return res.status(400).json({ error: 'Invalid duration' });
  const hashed = await bcrypt.hash(password, 10);
  const expiresAt = Date.now() + ms;
  users.push({ username, password: hashed, expiresAt });
  writeUsers(users);
  // create user folder
  const userDir = path.join(UPLOAD_DIR, username);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
  // schedule deletion based on custom duration (skip admin)
  if (username !== ADMIN_USERNAME) scheduleDeletion(username, ms);
  res.json({ message: 'User registered' });
});

// Login route
app.post('/auth/login', async (req, res) => {
  console.log('User logged in: ', req.body.username);
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    const users = readUsers();
    const userRec = users.find(u => u.username === username);
    if (!userRec) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const match = await bcrypt.compare(password, userRec.password);
    if (!match) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Auth middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  let token = null;
  if (authHeader) {
    token = authHeader.split(' ')[1];
  } else if (req.query && req.query.token) {
    token = req.query.token;
  }
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded.username;
    next();
  });
}

// Storage with per-user directory
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(UPLOAD_DIR, req.user);
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// Upload endpoint (protected)
app.post('/upload', authenticate, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  // Audit log: upload
  const uploadLogs = readLogs();
  uploadLogs.push({ timestamp: Date.now(), user: req.user, action: 'upload', fileName: req.file.filename });
  writeLogs(uploadLogs);
  const fileUrl = `${req.protocol}://${req.get('host')}/files/${req.file.filename}`;
  res.json({ fileName: req.file.filename, originalName: req.file.originalname, url: fileUrl });
});

// Add queue system for chunk merging
const mergeQueue = new Map(); // Map of user -> queue of files to merge
const MAX_CONCURRENT_MERGES = 3; // Maximum number of concurrent merges per user
const MERGE_TIMEOUT = 5 * 60 * 1000; // 5 minutes timeout for merge operations

// Add a map to track chunk uploads
const chunkUploads = new Map(); // Map of user -> Map of fileName -> Set of uploaded chunks

// Helper to process merge queue for a user
async function processMergeQueue(username) {
  const queue = mergeQueue.get(username) || [];
  if (queue.length === 0) return;

  // Count active merges
  const activeMerges = queue.filter(item => item.status === 'merging').length;
  if (activeMerges >= MAX_CONCURRENT_MERGES) return;

  // Find next pending merge
  const nextMerge = queue.find(item => item.status === 'pending');
  if (!nextMerge) return;

  nextMerge.status = 'merging';
  const { fileName, totalChunks, resolve, reject } = nextMerge;

  try {
    const userDir = path.join(__dirname, UPLOAD_DIR, username);
    const chunkDir = path.join(userDir, `${fileName}_chunks`);
    const finalPath = path.join(userDir, fileName);
    const writeStream = fs.createWriteStream(finalPath);

    // Set timeout for merge operation
    const timeout = setTimeout(() => {
      reject(new Error('Merge operation timed out'));
      cleanupMerge(username, fileName);
      cleanupChunkTracking(username, fileName);
    }, MERGE_TIMEOUT);

    // Merge chunks
    for (let i = 0; i < totalChunks; i++) {
      const chunkPath = path.join(chunkDir, String(i));
      if (!fs.existsSync(chunkPath)) {
        throw new Error(`Missing chunk ${i}`);
      }
      const data = await fs.promises.readFile(chunkPath);
      await new Promise((resolve, reject) => {
        writeStream.write(data, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }

    // Wait for write stream to finish
    await new Promise((resolve, reject) => {
      writeStream.end(() => resolve());
    });

    // Clean up chunks
    await fs.promises.rm(chunkDir, { recursive: true, force: true });
    cleanupChunkTracking(username, fileName);

    // Log successful upload
    const uploadLogs = readLogs();
    uploadLogs.push({
      timestamp: Date.now(),
      user: username,
      action: 'upload',
      fileName: fileName
    });
    writeLogs(uploadLogs);

    clearTimeout(timeout);
    resolve(true);
  } catch (error) {
    console.error('Error merging chunks:', error);
    reject(error);
    cleanupChunkTracking(username, fileName);
  } finally {
    // Remove from queue and process next
    const index = queue.findIndex(item => item.fileName === fileName);
    if (index !== -1) {
      queue.splice(index, 1);
    }
    if (queue.length === 0) {
      mergeQueue.delete(username);
    } else {
      processMergeQueue(username);
    }
  }
}

// Helper to cleanup failed merges
function cleanupMerge(username, fileName) {
  const userDir = path.join(__dirname, UPLOAD_DIR, username);
  const chunkDir = path.join(userDir, `${fileName}_chunks`);
  const finalPath = path.join(userDir, fileName);
  
  try {
    if (fs.existsSync(chunkDir)) {
      fs.rmSync(chunkDir, { recursive: true, force: true });
    }
    if (fs.existsSync(finalPath)) {
      fs.unlinkSync(finalPath);
    }
  } catch (error) {
    console.error('Error cleaning up merge:', error);
  }
}

// Update chunks endpoint to use the tracking map
app.get('/upload/chunks', authenticate, (req, res) => {
  const { fileName } = req.query;
  if (!fileName) {
    return res.status(400).json({ error: 'fileName required' });
  }
  
  const userDir = path.join(__dirname, UPLOAD_DIR, req.user);
  const chunkDir = path.join(userDir, `${fileName}_chunks`);
  
  try {
    // Create chunk directory if it doesn't exist
    if (!fs.existsSync(chunkDir)) {
      fs.mkdirSync(chunkDir, { recursive: true });
    }
    
    // Get uploaded chunks from tracking map
    const userChunks = chunkUploads.get(req.user);
    let uploadedChunks = [];
    
    if (userChunks && userChunks.has(fileName)) {
      uploadedChunks = Array.from(userChunks.get(fileName)).sort((a, b) => a - b);
    } else {
      // Fallback to checking filesystem if not in tracking map
      if (fs.existsSync(chunkDir)) {
        uploadedChunks = fs.readdirSync(chunkDir)
          .map(f => Number(f))
          .filter(n => !isNaN(n))
          .sort((a, b) => a - b);
      }
    }
    
    res.json({ uploadedChunks });
  } catch (error) {
    console.error('Error checking chunks:', error);
    res.status(500).json({ error: 'Failed to check chunks' });
  }
});

// Update chunk upload endpoint to handle resumption
app.post('/upload/chunk', authenticate, express.raw({ type: 'application/octet-stream', limit: '100mb' }), async (req, res) => {
  const { fileName, chunkIndex, totalChunks } = req.query;
  if (!fileName || chunkIndex === undefined || totalChunks === undefined) {
    return res.status(400).json({ error: 'fileName, chunkIndex, and totalChunks required' });
  }
  const idx = Number(chunkIndex);
  const total = Number(totalChunks);
  const userDir = path.join(__dirname, UPLOAD_DIR, req.user);
  const chunkDir = path.join(userDir, `${fileName}_chunks`);
  
  try {
    // Ensure chunk directory exists
    fs.mkdirSync(chunkDir, { recursive: true });
    const chunkPath = path.join(chunkDir, String(idx));
    
    // Initialize user's chunk tracking if needed
    if (!chunkUploads.has(req.user)) {
      chunkUploads.set(req.user, new Map());
    }
    const userChunks = chunkUploads.get(req.user);
    if (!userChunks.has(fileName)) {
      userChunks.set(fileName, new Set());
    }
    const uploadedChunks = userChunks.get(fileName);
    
    // Check if chunk already exists and has the same size
    if (fs.existsSync(chunkPath)) {
      const existingSize = fs.statSync(chunkPath).size;
      const newSize = req.body.length;
      
      // If sizes match, assume chunk is already uploaded correctly
      if (existingSize === newSize) {
        uploadedChunks.add(idx);
        res.json({ 
          received: idx,
          status: idx + 1 === total ? 'queued_for_merge' : 'chunk_received',
          skipped: true,
          uploadedChunks: Array.from(uploadedChunks)
        });
        return;
      }
    }
    
    // Write new chunk
    fs.writeFileSync(chunkPath, req.body);
    uploadedChunks.add(idx);

    // If last chunk, add to merge queue
    if (idx + 1 === total) {
      const queue = mergeQueue.get(req.user) || [];
      const mergePromise = new Promise((resolve, reject) => {
        queue.push({
          fileName,
          totalChunks: total,
          status: 'pending',
          resolve,
          reject
        });
      });
      mergeQueue.set(req.user, queue);
      processMergeQueue(req.user);
    }
    
    res.json({ 
      received: idx,
      status: idx + 1 === total ? 'queued_for_merge' : 'chunk_received',
      skipped: false,
      uploadedChunks: Array.from(uploadedChunks)
    });
  } catch (error) {
    console.error('Error handling chunk upload:', error);
    res.status(500).json({ error: 'Failed to process chunk' });
  }
});

// Add endpoint to check merge status
app.get('/upload/merge-status', authenticate, (req, res) => {
  const { fileName } = req.query;
  if (!fileName) {
    return res.status(400).json({ error: 'fileName required' });
  }
  
  const queue = mergeQueue.get(req.user) || [];
  const mergeItem = queue.find(item => item.fileName === fileName);
  
  if (!mergeItem) {
    // Check if file exists (merge completed)
    const filePath = path.join(__dirname, UPLOAD_DIR, req.user, fileName);
    if (fs.existsSync(filePath)) {
      return res.json({ status: 'completed' });
    }
    return res.json({ status: 'not_found' });
  }
  
  res.json({ status: mergeItem.status });
});

// Upload status endpoint to get received chunks (protected)
app.get('/upload/status', authenticate, (req, res) => {
  const { fileName } = req.query;
  if (!fileName) {
    return res.status(400).json({ error: 'fileName required' });
  }
  const userDir = path.join(__dirname, UPLOAD_DIR, req.user);
  const chunkDir = path.join(userDir, `${fileName}_chunks`);
  let received = [];
  if (fs.existsSync(chunkDir)) {
    received = fs.readdirSync(chunkDir).map(f => Number(f));
  }
  res.json({ received });
});

// List files with metadata (protected)
app.get('/files', authenticate, (req, res) => {
  console.log('Files request received for user:', req.user);
  const userDir = path.join(__dirname, UPLOAD_DIR, req.user);
  console.log('User directory path:', userDir);
  
  try {
    // Create user directory if it doesn't exist
    if (!fs.existsSync(userDir)) {
      console.log('Creating user directory:', userDir);
      fs.mkdirSync(userDir, { recursive: true });
    }

    // Read directory contents
    console.log('Reading directory:', userDir);
    const files = fs.readdirSync(userDir);
    console.log('Found files:', files);

    const fileInfos = files.map(file => {
      try {
        const filePath = path.join(userDir, file);
        console.log('Processing file:', filePath);
        
        // Skip if not a file
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) {
          console.log('Skipping non-file:', filePath);
          return null;
        }

        // Extract timestamp from filename - look for a number at the start of the filename
        // Only match if the number is followed by a dash and the number is a reasonable timestamp
        const timestampMatch = file.match(/^(\d{13})-/) || file.match(/^(\d{10})-/);
        let uploadTimestamp;
        let originalName = file;
        
        if (timestampMatch) {
          // If we found a timestamp prefix, use it
          const timestampStr = timestampMatch[1];
          console.log('Found timestamp in filename:', timestampStr);
          
          // Validate timestamp is a reasonable Unix timestamp (between 2000 and 2100)
          const minTimestamp = new Date('2000-01-01').getTime();
          const maxTimestamp = new Date('2100-01-01').getTime();
          uploadTimestamp = Number(timestampStr);
          
          // If it's a 10-digit timestamp, convert to milliseconds
          if (timestampStr.length === 10) {
            uploadTimestamp *= 1000;
          }
          
          if (isNaN(uploadTimestamp) || uploadTimestamp < minTimestamp || uploadTimestamp > maxTimestamp) {
            console.log('Invalid timestamp range, using file stats');
            uploadTimestamp = stats.birthtimeMs || stats.ctimeMs;
          } else {
            console.log('Using timestamp from filename:', new Date(uploadTimestamp).toISOString());
          }
          
          originalName = file.slice(timestampMatch[0].length);
        } else {
          console.log('No timestamp in filename, using file stats');
          uploadTimestamp = stats.birthtimeMs || stats.ctimeMs;
        }
        
        // Ensure timestamp is valid
        if (isNaN(uploadTimestamp) || uploadTimestamp <= 0) {
          console.log('Invalid timestamp from stats, using current time');
          uploadTimestamp = Date.now();
        }
        
        const ext = path.extname(originalName).slice(1).toLowerCase();
        const size = stats.size;
        
        // Create date object and validate it
        let date;
        try {
          date = new Date(uploadTimestamp);
          if (isNaN(date.getTime())) {
            throw new Error('Invalid date');
          }
          console.log('Created valid date:', date.toISOString());
        } catch (dateErr) {
          console.log('Invalid date created, using current time');
          date = new Date();
        }
        
        const fileInfo = { 
          fileName: file, 
          originalName, 
          dateUploaded: date.toISOString(), 
          type: ext, 
          size 
        };
        console.log('Processed file info:', fileInfo);
        return fileInfo;
      } catch (fileErr) {
        console.error(`Error processing file ${file}:`, fileErr);
        console.error('Error stack:', fileErr.stack);
        // Return a safe fallback for this file
        return {
          fileName: file,
          originalName: file,
          dateUploaded: new Date().toISOString(),
          type: 'unknown',
          size: 0
        };
      }
    }).filter(info => info !== null); // Remove any null entries
    
    console.log('Processed file infos:', fileInfos);
    
    // Apply search and sort filters based on query params
    const { search, sortBy, order } = req.query;
    let result = fileInfos;
    
    if (search) {
      const lower = search.toLowerCase();
      result = result.filter(f =>
        f.originalName.toLowerCase().includes(lower) ||
        f.type.toLowerCase().includes(lower)
      );
    }
    
    if (sortBy) {
      result.sort((a, b) => {
        try {
          if (sortBy === 'dateUploaded') {
            return new Date(a.dateUploaded).getTime() - new Date(b.dateUploaded).getTime();
          }
          if (sortBy === 'name') return a.originalName.localeCompare(b.originalName);
          if (sortBy === 'type') return a.type.localeCompare(b.type);
          if (sortBy === 'size') return a.size - b.size;
          return 0;
        } catch (sortErr) {
          console.error('Error sorting files:', sortErr);
          return 0;
        }
      });
      if (order === 'desc') result.reverse();
    }
    
    console.log('Sending response with', result.length, 'files');
    res.json(result);
  } catch (err) {
    console.error('Error scanning files:', err);
    console.error('Error stack:', err.stack);
    
    // Get detailed error information
    const errorInfo = {
      error: 'Unable to scan files',
      details: err.message,
      stack: err.stack,
      user: req.user,
      userDir: userDir,
      exists: fs.existsSync(userDir),
      isDirectory: fs.existsSync(userDir) ? fs.statSync(userDir).isDirectory() : false,
      files: fs.existsSync(userDir) ? fs.readdirSync(userDir) : [],
      permissions: fs.existsSync(userDir) ? {
        mode: fs.statSync(userDir).mode,
        uid: fs.statSync(userDir).uid,
        gid: fs.statSync(userDir).gid
      } : null,
      processInfo: {
        uid: process.getuid(),
        gid: process.getgid(),
        cwd: process.cwd()
      }
    };
    
    console.error('Error details:', errorInfo);
    res.status(500).json(errorInfo);
  }
});

// Bulk download as ZIP via GET (protected)
app.get('/files/zip', authenticate, (req, res) => {
  let fileNames = req.query.files;
  if (!fileNames) {
    return res.status(400).json({ error: 'No files specified' });
  }
  if (!Array.isArray(fileNames)) {
    fileNames = [fileNames];
  }
  const archive = archiver('zip', { zlib: { level: 9 } });
  res.attachment('files.zip');
  archive.pipe(res);
  fileNames.forEach(file => {
    const filePath = path.join(__dirname, UPLOAD_DIR, req.user, file);
    if (fs.existsSync(filePath)) {
      const dashIndex = file.indexOf('-');
      const originalName = dashIndex !== -1 ? file.slice(dashIndex + 1) : file;
      archive.file(filePath, { name: originalName });
    }
  });
  archive.finalize();
});

// Download endpoint (protected)
app.get('/files/:filename', authenticate, (req, res) => {
  const file = req.params.filename;
  const filePath = path.join(__dirname, UPLOAD_DIR, req.user, file);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  // Audit log: download (only when explicitly requested)
  if (req.query.download === 'true') {
    const downloadLogs = readLogs();
    downloadLogs.push({ timestamp: Date.now(), user: req.user, action: 'download', fileName: file });
    writeLogs(downloadLogs);
  }
  // Strip timestamp prefix for the download filename
  const dashIndex = file.indexOf('-');
  const originalName = dashIndex !== -1 ? file.slice(dashIndex + 1) : file;
  res.download(filePath, originalName);
});

// Delete file (protected)
app.delete('/files/:filename', authenticate, (req, res) => {
  const filePath = path.join(__dirname, UPLOAD_DIR, req.user, req.params.filename);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  try {
    fs.unlinkSync(filePath);
    // Audit log: delete
    const deleteLogs = readLogs();
    deleteLogs.push({ timestamp: Date.now(), user: req.user, action: 'delete', fileName: req.params.filename });
    writeLogs(deleteLogs);
    res.json({ message: 'File deleted' });
  } catch (err) {
    console.error('Error deleting file', err);
    res.status(500).json({ error: 'Unable to delete file' });
  }
});

// Rename file (protected)
app.put('/files/:filename/rename', authenticate, express.json(), (req, res) => {
  const oldName = req.params.filename;
  const { newName } = req.body;
  if (!newName) return res.status(400).json({ error: 'newName required' });
  const userDir = path.join(__dirname, UPLOAD_DIR, req.user);
  const oldPath = path.join(userDir, oldName);
  if (!fs.existsSync(oldPath)) return res.status(404).json({ error: 'File not found' });
  // Preserve prefix timestamp
  const dashIndex = oldName.indexOf('-');
  const prefix = dashIndex !== -1 ? oldName.slice(0, dashIndex) : Date.now().toString();
  // Sanitize newName: remove path separators
  const sanitized = path.basename(newName);
  const newFileName = `${prefix}-${sanitized}`;
  const newPath = path.join(userDir, newFileName);
  try {
    fs.renameSync(oldPath, newPath);
    res.json({ fileName: newFileName, originalName: sanitized });
  } catch (err) {
    console.error('Rename error:', err);
    res.status(500).json({ error: 'Unable to rename file' });
  }
});

// Get user profile (email, time left, storage usage)
app.get('/auth/profile', authenticate, (req, res) => {
  const users = readUsers();
  const u = users.find(u => u.username === req.user);
  if (!u) return res.status(404).json({ error: 'User not found' });
  // Determine timeLeft, never expire for admin
  const timeLeft = (u.username === ADMIN_USERNAME)
    ? 10 * 365 * 24 * 3600 * 1000
    : Math.max(0, u.expiresAt - Date.now());
  const userDir = path.join(__dirname, UPLOAD_DIR, req.user);
  let storageUsed = 0;
  if (fs.existsSync(userDir)) {
    fs.readdirSync(userDir).forEach(file => {
      const stats = fs.statSync(path.join(userDir, file));
      storageUsed += stats.size;
    });
  }
  res.json({ username: u.username, email: u.email || '', timeLeft, storageUsed, isAdmin: u.username === ADMIN_USERNAME });
});

// Update email
app.put('/auth/profile/email', authenticate, (req, res) => {
  const { email } = req.body;
  if (email === undefined) return res.status(400).json({ error: 'Email required' });
  const users = readUsers();
  const u = users.find(u => u.username === req.user);
  if (!u) return res.status(404).json({ error: 'User not found' });
  u.email = email;
  writeUsers(users);
  res.json({ message: 'Email updated', email });
});

// Update password
app.put('/auth/profile/password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'currentPassword and newPassword required' });
  const users = readUsers();
  const u = users.find(u => u.username === req.user);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const match = await bcrypt.compare(currentPassword, u.password);
  if (!match) return res.status(400).json({ error: 'Invalid current password' });
  u.password = await bcrypt.hash(newPassword, 10);
  writeUsers(users);
  res.json({ message: 'Password updated' });
});

// Extend session expiration
app.put('/auth/session', authenticate, (req, res) => {
  const { durationMs } = req.body;
  const ms = Number(durationMs);
  if (!ms || ms <= 0) return res.status(400).json({ error: 'Invalid duration' });
  const users = readUsers();
  const u = users.find(u => u.username === req.user);
  if (!u) return res.status(404).json({ error: 'User not found' });
  // For admin, we leave expiresAt untouched (never expire)
  if (req.user !== ADMIN_USERNAME) {
    u.expiresAt = Date.now() + ms;
    writeUsers(users);
    scheduleDeletion(req.user, ms);
  }
  res.json({ timeLeft: ms });
});

// Session endpoint to get time left
app.get('/auth/session', authenticate, (req, res) => {
  // Admin never expires
  if (req.user === ADMIN_USERNAME) {
    // return a very large time (10 years in ms)
    return res.json({ timeLeft: 10 * 365 * 24 * 3600 * 1000 });
  }
  const users = readUsers();
  const u = users.find(u => u.username === req.user);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const timeLeft = Math.max(0, u.expiresAt - Date.now());
  res.json({ timeLeft });
});

// Bulk download as ZIP (protected)
app.post('/files/zip', authenticate, (req, res) => {
  const { files: fileNames } = req.body;
  if (!Array.isArray(fileNames) || fileNames.length === 0) {
    return res.status(400).json({ error: 'No files specified for ZIP download' });
  }
  const archive = archiver('zip', { zlib: { level: 9 } });
  // Set headers
  res.attachment('files.zip');
  // Pipe archive data to response
  archive.pipe(res);
  // Append files
  fileNames.forEach(file => {
    const filePath = path.join(__dirname, UPLOAD_DIR, req.user, file);
    if (fs.existsSync(filePath)) {
      const dashIndex = file.indexOf('-');
      const originalName = dashIndex !== -1 ? file.slice(dashIndex + 1) : file;
      archive.file(filePath, { name: originalName });
    }
  });
  archive.finalize();
});

// Create a shareable link for a single file (protected)
app.post('/files/share', authenticate, async (req, res) => {
  const { fileName, expiresIn, password } = req.body;
  if (!fileName || !expiresIn) {
    return res.status(400).json({ error: 'fileName and expiresIn required' });
  }
  const filePath = path.join(__dirname, UPLOAD_DIR, req.user, fileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  const token = crypto.randomUUID();
  const expiresAt = Date.now() + Number(expiresIn) * 1000;
  let passwordHash = null;
  if (password) {
    passwordHash = await bcrypt.hash(password, 10);
  }
  const shares = readShares();
  shares.push({ token, user: req.user, fileName, expiresAt, passwordHash });
  writeShares(shares);
  const shareLink = `${req.protocol}://${req.get('host')}/share/${token}`;
  res.json({ shareLink });
});

// Download via shareable link (public)
app.get('/share/:token', async (req, res) => {
  const shares = readShares();
  const share = shares.find(s => s.token === req.params.token);
  if (!share) return res.status(404).send('Invalid share link');
  if (Date.now() > share.expiresAt) {
    return res.status(410).send('Share link expired');
  }
  // Helper to render password prompt page
  const renderForm = (error) => `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Protected Download</title>
<style>
  body {
    margin: 0;
    font-family: 'Segoe UI', Tahoma, sans-serif;
    background-color: #2f3136;
    display: flex;
    align-items: center;
    justify-content: center;
    height: 100vh;
  }
  .form-container {
    background-color: #36393f;
    padding: 30px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    width: 320px;
    color: #dcddde;
    text-align: center;
  }
  .form-container h2 {
    margin: 0 0 20px;
    font-size: 1.5rem;
  }
  .form-container .error {
    background-color: #f04747;
    color: #fff;
    padding: 8px;
    border-radius: 4px;
    margin-bottom: 15px;
    font-size: 0.9em;
  }
  .form-container input[type="password"],
  .form-container button {
    display: block;
    width: 80%;
    margin: 10px auto;
  }
  .form-container input[type="password"] {
    padding: 10px;
    border: none;
    border-radius: 4px;
    background-color: #202225;
    color: #dcddde;
  }
  .form-container button {
    padding: 12px;
    background-color: #7289da;
    color: #fff;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.2s ease;
  }
  .form-container button:hover {
    background-color: #5b6eae;
  }
</style></head><body>
<div class="form-container">
  <h2>Protected File</h2>
  ${error?`<div class="error">${error}</div>`:''}
  <form method="get" action="/share/${share.token}">
    <input type="password" name="password" placeholder="Enter password" required />
    <button type="submit">Download</button>
  </form>
</div>
</body></html>`;
  if (share.passwordHash) {
    const provided = req.query.password;
    if (!provided) {
      return res.status(200).send(renderForm());
    }
    const ok = await bcrypt.compare(provided, share.passwordHash);
    if (!ok) {
      return res.status(200).send(renderForm('Invalid password'));
    }
  }
  const filePath = path.join(__dirname, UPLOAD_DIR, share.user, share.fileName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }
  const dashIndex = share.fileName.indexOf('-');
  const originalName = dashIndex !== -1 ? share.fileName.slice(dashIndex + 1) : share.fileName;
  res.download(filePath, originalName);
});

// Get activity/audit logs for current user
app.get('/auth/logs', authenticate, (req, res) => {
  const allLogs = readLogs();
  const userLogs = allLogs.filter(entry => entry.user === req.user);
  res.json({ logs: userLogs });
});

// === Admin Dashboard Routes ===
// List all user accounts with storage usage and time left
app.get('/admin/users', authenticateAdmin, (req, res) => {
  const users = readUsers();
  const userInfos = users.map(u => {
    const timeLeft = Math.max(0, u.expiresAt - Date.now());
    const userDir = path.join(__dirname, UPLOAD_DIR, u.username);
    let storageUsed = 0;
    if (fs.existsSync(userDir)) {
      fs.readdirSync(userDir).forEach(file => {
        const stats = fs.statSync(path.join(userDir, file));
        storageUsed += stats.size;
      });
    }
    return { username: u.username, timeLeft, storageUsed };
  });
  res.json({ users: userInfos });
});

// Delete a user account and all their data
app.delete('/admin/users/:username', authenticateAdmin, (req, res) => {
  const target = req.params.username;
  if (!readUsers().some(u => u.username === target)) {
    return res.status(404).json({ error: 'User not found' });
  }
  deleteUser(target);
  res.json({ message: `User ${target} deleted` });
});

// Extend or reset session for a user
app.put('/admin/users/:username/session', authenticateAdmin, (req, res) => {
  const { durationMs } = req.body;
  const ms = Number(durationMs);
  if (!ms || ms <= 0) return res.status(400).json({ error: 'Invalid duration' });
  const users = readUsers();
  const u = users.find(u => u.username === req.params.username);
  if (!u) return res.status(404).json({ error: 'User not found' });
  u.expiresAt = Date.now() + ms;
  writeUsers(users);
  scheduleDeletion(req.params.username, ms);
  res.json({ username: u.username, timeLeft: ms });
});

// Cleanup: delete all expired users
app.delete('/admin/cleanup', authenticateAdmin, (req, res) => {
  const users = readUsers();
  const now = Date.now();
  const expired = users.filter(u => u.expiresAt <= now).map(u => u.username);
  expired.forEach(username => deleteUser(username));
  res.json({ deletedUsers: expired });
});

// Add cleanup for chunk tracking
function cleanupChunkTracking(username, fileName) {
  const userChunks = chunkUploads.get(username);
  if (userChunks) {
    userChunks.delete(fileName);
    if (userChunks.size === 0) {
      chunkUploads.delete(username);
    }
  }
}

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`)); 