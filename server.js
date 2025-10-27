
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const db = require('./db');
const path = require('path');
const mysql = require('mysql');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const nodemailer = require("nodemailer");
require('dotenv').config();

const app = express();
const PORT = 5000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], (err) => {
    if (err) {
      return res.send('❌ Username already exists or error saving user.');
    }
    res.redirect('/index.html');
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) {
      return res.send('❌ Invalid username');
    }

    const isMatch = await bcrypt.compare(password, results[0].password);
    if (isMatch) {
      res.redirect('/driverform.html');
    } else {
      res.send('❌ Incorrect password');
    }
  });
});

app.post('/register1', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.query('INSERT INTO customer (username, password) VALUES (?, ?)', [username, hashed], (err) => {
    if (err) {
      return res.send('❌ Username already exists or error saving user.');
    }
    res.redirect('/userlogin.html');
  });
});

// userLogin endpoint
app.post('/login1', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM customer WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) {
      return res.send('❌ Invalid username');
    }

    const isMatch = await bcrypt.compare(password, results[0].password);
    if (isMatch) {
      res.redirect(`/user_home.html?username=${encodeURIComponent(username)}`);
    } else {
      res.send('❌ Incorrect password');
    }
  });
});
app.get("/api/rides", (req, res) => {
  const { src, dest } = req.query;
  const sql = "SELECT * FROM auto_list WHERE src = ? AND dest = ?";
  db.query(sql, [src, dest], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});
app.post('/driverdata', (req, res) => {
  const { dr_name, id, src, dest, price, email_id, auto_id } = req.body;

  const sql = 'INSERT INTO auto_list (dr_name, id, src, dest, price, email_id, auto_id) VALUES (?, ?, ?, ?, ?, ?, ?)';
  db.query(sql, [dr_name, id, src, dest, price, email_id, auto_id], (err) => {
    if (err) {
      console.error(err);
      return res.send('❌ Details are not properly stored! Please try again.');
    }
    res.redirect('/driversuccess.html');
  });
});
app.get("/api/active-drivers", (req, res) => {
  const sql = "SELECT COUNT(*) AS count FROM auto_list WHERE status = 'Available'";
  db.query(sql, (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Database query error" });
    } else {
      res.json({ count: result[0].count });
    }
  });
});

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// simple endpoint to expose Key ID to client (safe)
app.get('/get-key', (req, res) => {
  res.json({ key: process.env.RAZORPAY_KEY_ID || '' });
});

// create order - called by frontend
app.post('/create-order', async (req, res) => {
  try {
    const { amount } = req.body; // amount in INR e.g. 100
    if (!amount) return res.status(400).json({ error: 'Amount is required' });

    const amountInPaise = Math.round(Number(amount) * 100); // Razorpay expects smallest currency unit
    const options = {
      amount: amountInPaise,
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
      payment_capture: 1 // auto-capture
    };

    const order = await razorpay.orders.create(options);
    // send order to client
    res.json(order);
  } catch (err) {
    console.error('create-order error:', err);
    res.status(500).json({ error: 'Unable to create order' });
  }
});

// verify payment signature (mandatory)
app.post('/verify', (req, res) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;
  if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
    return res.status(400).json({ status: 'error', message: 'Missing parameters' });
  }

  const body = razorpay_order_id + '|' + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body)
    .digest('hex');

  if (expectedSignature === razorpay_signature) {
    return res.json({ status: 'ok', message: 'Payment verified successfully' });
  } else {
    return res.status(400).json({ status: 'fail', message: 'Invalid signature' });
  }
});


// booking route
app.post('/book', (req, res) => {
  const { date, pickup, destination, name, ph_no, email, address, status, amount, email_id, auto_id } = req.body;

  const sql = `INSERT INTO booking1 
    (date, pickup, destination, name, ph_no, email, address, status, amount, email_id, auto_id) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  db.query(sql, [date, pickup, destination, name, ph_no, email, address, status, amount, email_id, auto_id], (err, result) => {
    if (err) {
      console.error("❌ DB insert error:", err);
      return res.status(500).send("Database insert failed.");
    }

    // Build email content using the inserted booking data
    const messageBody = `
Ride Confirmation
--------------------
Auto ID: ${auto_id}
Name: ${name}
Pickup: ${pickup}
Destination: ${destination}
Date: ${date}
Amount: ${amount}
Phone: ${ph_no}
Address: ${address}
Payment Status: ${status}
`;

    // Create Nodemailer transporter (Gmail example)
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email_id, // email_id from the booking form / DB column
      subject: `New Booking: ${name} - ${date}`,
      text: messageBody
    };

    // Send the email, then redirect to receipt regardless of email success
    transporter.sendMail(mailOptions, (mailErr, info) => {
      if (mailErr) {
        console.error("❌ Error sending email:", mailErr);
        // Booking already stored. Redirect with an email error flag if you'd like.
        return res.redirect(`/receipt.html?name=${encodeURIComponent(name)}&emailError=1`);
      }

      console.log("✅ Email sent:", info.response);
      // All good: redirect to receipt page
      return res.redirect(`/receipt.html?name=${encodeURIComponent(name)}`);
    });
  });
});

// ------------------ PDF Generation Route ------------------
app.get('/booking/pdf', (req, res) => {
  const name = req.query.name;
  if (!name) return res.status(400).send('Name is required');

  // fetch latest booking for this name
  const sql = `SELECT * FROM booking1 WHERE name = ? ORDER BY id DESC LIMIT 1`;
  db.query(sql, [name], (err, results) => {
    if (err) return res.status(500).send('Database error');
    if (results.length === 0) return res.status(404).send('Booking not found');

    const booking = results[0];
    const doc = new PDFDocument({ size: 'A4', margin: 50 });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="booking-${booking.name}.pdf"`);

    doc.pipe(res);

    doc.fontSize(20).text('K-Ride Booking Receipt', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Passenger Name: ${booking.name}`);
    doc.text(`Phone: ${booking.ph_no}`);
    doc.text(`Email: ${booking.email}`);
    doc.text(`Auto Number: ${booking.auto_id}`);
    doc.text(`Pickup: ${booking.pickup}`);
    doc.text(`Destination: ${booking.destination}`);
    doc.text(`Address: ${booking.address}`);
    doc.text(`Date: ${booking.date}`);
    doc.text(`Status: ${booking.status}`);
    doc.text(`Amount: ₹${Number(booking.amount || 0).toFixed(2)}`);

    doc.moveDown(2);
    doc.fontSize(10).fillColor('gray').text('Thank you for choosing K-Ride!', { align: 'center' });

    doc.end();
  });
});

app.get('/api/bookings', (req, res) => {
  const sql = `SELECT name, pickup, destination, status, amount 
               FROM booking1
               ORDER BY id DESC 
               LIMIT 10`;

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching bookings:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(results);
  });
});

app.get("/api/active-rides", (req, res) => {
  const sql = "SELECT COUNT(*) AS count FROM booking1";
  db.query(sql, (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Database query error" });
    } else {
      res.json({ count: result[0].count });
    }
  });
});

app.get("/api/active-pending", (req, res) => {
  const sql = "SELECT COUNT(*) AS count FROM booking1 WHERE status = 'Pending'";
  db.query(sql, (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: "Database query error" });
    } else {
      res.json({ count: result[0].count });
    }
  });
});



app.get('/api/earnings', (req, res) => {
  const sql = "SELECT SUM(amount) AS totalEarnings FROM booking1 WHERE status = 'Paid'";

  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error fetching earnings:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json({ totalEarnings: results[0].totalEarnings || 0 });
  });
});


const COHERE_API_KEY = process.env.COHERE_API_KEY || null;
const COHERE_MODEL = process.env.COHERE_MODEL || 'command-a-03-2025'; // override if you use another model

const chatHistories = {}; // { sessionId: [ { role: 'USER'|'CHATBOT'|'SYSTEM', message: '...' } ] }
const HISTORY_TURN_LIMIT = 12; // keep last N turns (~user+bot pairs)

function cleanContent(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).replace(/\u00A0/g, ' ').trim();
  return s.length ? s : null;
}

function pushHistory(sessionId, role, message) {
  if (!chatHistories[sessionId]) chatHistories[sessionId] = [];
  chatHistories[sessionId].push({ role, message });
  const max = HISTORY_TURN_LIMIT * 2; // approximate entries
  if (chatHistories[sessionId].length > max) {
    chatHistories[sessionId] = chatHistories[sessionId].slice(-max);
  }
}

app.post('/chat', async (req, res) => {
  const rawMessage = req.body.message;
  const rawSession = req.body.sessionId || req.headers['x-session-id'];
  const userMessage = cleanContent(rawMessage);
  if (!userMessage) return res.status(400).json({ reply: 'Empty message' });

  let sessionId = rawSession;
  if (!sessionId) sessionId = 's_' + Math.random().toString(36).slice(2, 12);

  // build chat_history (v1 expects list of { role: 'USER'|'CHATBOT'|'SYSTEM', message: '...' })
  const prev = chatHistories[sessionId] || [];
  const chat_history = [];

  // optional: include a system/preamble entry (v1 docs recommend preamble param for system-level prompts)
  // If you prefer to use preamble, move this to the request's "preamble" instead of chat_history.
  // chat_history.push({ role: 'SYSTEM', message: 'You are K Ride support assistant...' });

  for (const entry of prev) {
    if (!entry || !entry.role) continue;
    const cleaned = cleanContent(entry.message);
    if (!cleaned) continue;
    // v1 expects uppercase roles: USER, CHATBOT, SYSTEM
    const roleUpper = String(entry.role).toUpperCase();
    if (['USER', 'CHATBOT', 'SYSTEM'].includes(roleUpper)) {
      chat_history.push({ role: roleUpper, message: cleaned });
    }
  }

  // Add the current user turn as the `message` (v1 requires `message` string)
  // Note: chat_history should exclude the current user turn per v1 docs (it's passed in message)
  // So we do NOT push the current user into chat_history here; we pass it as `message`.
  // (We will save both user and bot to history AFTER a successful response.)
  const payload = {
    // v1 shape: `message` (the current user turn)
    message: userMessage,
    // optional: chat_history (previous turns)
    chat_history
    // you may include model, preamble, max_tokens, temperature, etc.
  };

  if (COHERE_MODEL) payload.model = COHERE_MODEL;

  // DEBUG log payload (truncated content)
  console.log('>> Cohere V1 payload (session:', sessionId, ')', JSON.stringify(
    { message: payload.message, chat_history: payload.chat_history.map(h => ({ role: h.role, message: (h.message.length>300? h.message.slice(0,300)+'...' : h.message) })) },
    null, 2
  ));

  // If no API key, use rule-based fallback and save to local history
  if (!COHERE_API_KEY) {
    const lower = userMessage.toLowerCase();
    let fallback = "I'm sorry, I didn't understand that. Could you provide more details?";
    if (lower.includes('book') || lower.includes('pickup') || lower.includes('drop')) fallback = "Login → add pickup & drop → auto list shows vehicles → select & book.";
    else if (lower.includes('payment') || lower.includes('pay')) fallback = "Check payment method in app settings or contact support@kride.com.";
    else if (lower.includes('cancel')) fallback = "Go to Active Ride → Cancel Ride. Cancellation fees may apply.";
    else if (lower.includes('safety') || lower.includes('emergency')) fallback = "If unsafe, use emergency button in the app to alert authorities immediately.";

    pushHistory(sessionId, 'USER', userMessage);
    pushHistory(sessionId, 'CHATBOT', fallback);
    return res.json({ reply: fallback, sessionId });
  }

  try {
    const r = await fetch('https://api.cohere.ai/v1/chat', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${COHERE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!r.ok) {
      const text = await r.text().catch(() => '<no-body>');
      console.error('Cohere non-200:', r.status, text);
      const fallback = "We are experiencing issues contacting the language service. Please try again later.";
      pushHistory(sessionId, 'USER', userMessage);
      pushHistory(sessionId, 'CHATBOT', fallback);
      return res.status(502).json({ reply: fallback, sessionId });
    }

    const data = await r.json();

    // v1 response shape: data.message.content[0].text
    let botReply = null;
    if (data && data.message && Array.isArray(data.message.content) && data.message.content[0] && typeof data.message.content[0].text === 'string') {
      botReply = data.message.content[0].text.trim();
    } else if (data && typeof data.output === 'string') {
      botReply = data.output.trim();
    }

    if (!botReply) {
      console.error('Unexpected Cohere response shape:', JSON.stringify(data).slice(0,2000));
      const fallback = "The assistant returned an unexpected response. Try again later.";
      pushHistory(sessionId, 'USER', userMessage);
      pushHistory(sessionId, 'CHATBOT', fallback);
      return res.status(502).json({ reply: fallback, sessionId });
    }

    // Save conversation (user + assistant)
    pushHistory(sessionId, 'USER', userMessage);
    pushHistory(sessionId, 'CHATBOT', botReply);

    return res.json({ reply: botReply, sessionId });
  } catch (err) {
    console.error('Error calling Cohere:', err);
    const fallback = "Server error while contacting language service. Try again later.";
    pushHistory(sessionId, 'USER', userMessage);
    pushHistory(sessionId, 'CHATBOT', fallback);
    return res.status(500).json({ reply: fallback, sessionId });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
