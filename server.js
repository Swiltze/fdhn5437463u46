const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const sharedsession = require('express-socket.io-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;

// Set up session middleware
const sessionMiddleware= session({
  secret: 'secret key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // for development, set to true in production with HTTPS
});
app.use(sessionMiddleware);

io.use (sharedsession(sessionMiddleware, {
  autoSave: true
}));

// Set up EJS templating
app.set('view engine', 'ejs');

// Serve static files
app.use(express.static('public'));

// Body parser middleware to parse form data
app.use(express.urlencoded({ extended: true }));

// Initialize SQLite database
const db = new sqlite3.Database('./db/chatdb.sqlite', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the SQLite database.');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
});

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  // U like hash? 
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error(err)
      res.redirect('/');
    } else {
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
    if (err) {
      res.redirect('/');
        } else {
          req.session.userId = this.lastID;
          res.redirect('/chat');
        }
      });
    }
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // In a real application, you should compare the hashed password
  db.get('SELECT id, password FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      res.redirect('/');
    } else if (row) {
      //mm ur getting hash
      bcrypt.compare(password, row.password, (err, result) => {
        if (result) {
          req.session.userId = row.id;
          res.redirect('/chat');
        } else {
          res.redirect('/');
        }
      });
    } else {
      res.redirect('/');
    }
  });
});

app.get('/chat', (req, res) => {
  if (req.session.userId) {
    res.render('chat');
  } else {
    res.redirect('/');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Socket.IO events
io.on('connection', (socket) => {
  console.log('a user connected');
  db.all('SELECT message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 10', (err, rows) => {
    if (err) {  
      console.error(err);
      return
    }
  socket.emit('chatHistory', rows.reverse());
  });

  socket.on('chatMessage', (msg) => {
    const userId = req.session.userId;
    if (userId) {
      db.get('SELECT username FROM users WHERE id =?', [userId], (err, row) => {
        if (err) {
          console.error(err);
          return;
        }
        const username = row.username;
        db.run('INSERT INTO messages (user_id, message) VALUES (?, ?, ?)', [userId, username, msg], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          io.emit('chatMessage', { username, message: msg, timestamp: new Date() });
        });
      });
   }
  });

  socket.on('disconnect', () => {
    console.log('user disconnected');
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
