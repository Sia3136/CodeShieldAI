export const sampleCodes = {
  vulnerable: `// Example: Vulnerable Authentication System

const express = require('express');
const app = express();

// ❌ Hardcoded credentials
const ADMIN_PASSWORD = "admin123";
const API_KEY = "sk_live_1234567890abcdef";
const DB_PASSWORD = "mySecretPassword123";

// ❌ SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// ❌ XSS vulnerability
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  document.getElementById('comments').innerHTML += comment;
  res.send('Comment added');
});

// ❌ Command injection
app.get('/files', (req, res) => {
  const filename = req.query.file;
  exec('cat ' + filename, (error, stdout) => {
    res.send(stdout);
  });
});

// ❌ eval() usage
app.post('/calculate', (req, res) => {
  const expression = req.body.expr;
  const result = eval(expression);
  res.json({ result });
});

// ❌ Insecure random number generation
function generateToken() {
  return Math.random().toString(36).substring(7);
}

// ❌ Unvalidated redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});`,

  secure: `// Example: Secure Authentication System

const express = require('express');
const crypto = require('crypto');
const app = express();

// ✅ Environment variables for secrets
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;

// ✅ Parameterized queries prevent SQL injection
app.get('/user/:id', async (req, res) => {
  const userId = req.params.id;
  const query = "SELECT * FROM users WHERE id = ?";
  try {
    const results = await db.query(query, [userId]);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ✅ XSS prevention with sanitization
const DOMPurify = require('dompurify');
app.post('/comment', (req, res) => {
  const comment = DOMPurify.sanitize(req.body.comment);
  // Or use textContent instead of innerHTML
  res.send('Comment added safely');
});

// ✅ Safe command execution
const { execFile } = require('child_process');
app.get('/files', (req, res) => {
  const filename = req.query.file;
  
  // Validate filename
  if (!/^[a-zA-Z0-9_.-]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  execFile('cat', [filename], (error, stdout) => {
    if (error) {
      return res.status(500).json({ error: 'File read error' });
    }
    res.send(stdout);
  });
});

// ✅ Safe expression evaluation with validation
app.post('/calculate', (req, res) => {
  const expression = req.body.expr;
  
  // Validate expression only contains numbers and operators
  if (!/^[0-9+\\-*\\/()\\s]+$/.test(expression)) {
    return res.status(400).json({ error: 'Invalid expression' });
  }
  
  try {
    const result = new Function('return ' + expression)();
    res.json({ result });
  } catch (err) {
    res.status(400).json({ error: 'Calculation error' });
  }
});

// ✅ Cryptographically secure random number generation
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ✅ Validated redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  
  // Whitelist allowed domains
  const allowedDomains = ['example.com', 'trusted.com'];
  const urlObj = new URL(url);
  
  if (!allowedDomains.includes(urlObj.hostname)) {
    return res.status(400).json({ error: 'Invalid redirect URL' });
  }
  
  res.redirect(url);
});`,

  python: `# Example: Python Security Issues

import os
import subprocess

# ❌ Hardcoded credentials
API_KEY = "sk_test_abcdef123456"
PASSWORD = "mypassword123"

# ❌ SQL Injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# ❌ Command Injection
def list_files(directory):
    command = f"ls -la {directory}"
    os.system(command)

# ❌ eval() usage
def calculate(expression):
    return eval(expression)

# ❌ Insecure deserialization
import pickle
def load_data(data):
    return pickle.loads(data)`,

  javascript: `// Example: JavaScript Security Issues

// ❌ XSS vulnerability
function displayMessage(msg) {
  document.getElementById('output').innerHTML = msg;
}

// ❌ Prototype pollution
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];
  }
  return target;
}

// ❌ eval() usage
function executeCode(code) {
  eval(code);
}

// TODO: Fix this security issue
// FIXME: Add input validation`
};
