const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

const SECRET_KEY = 'hardcoded-secret-for-demo';

app.get('/greet', (req, res) => {
  const name = req.query.name;
  // XSS (CWE-79)
  res.send(`<h1>Hello, ${name}!</h1>`);
});

app.get('/download', (req, res) => {
  const file = req.query.file;
  // Path traversal (CWE-22)
  const data = fs.readFileSync(path.join('/data/', file));
  res.send(data);
});

app.listen(3000);
