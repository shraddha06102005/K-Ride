// db.js
const mysql = require('mysql2');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',       // Default XAMPP MySQL username
  password: '',       // Leave blank unless you set a password
  database: 'user_auth_system'
});

db.connect((err) => {
  if (err) throw err;
  console.log('✅ Connected to MySQL!');
});

module.exports = db;
