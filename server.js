const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const sharedsession = require('express-socket.io-session');
const bcrypt = require('bcrypt');
const saltRounds = 10;
const validator = require('validator');

// Set up session middleware
const sessionMiddleware = session({
  secret: 'secret key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // for development, set to true in production with HTTPS
});
app.use(sessionMiddleware);

io.use(sharedsession(sessionMiddleware, {
  autoSave: true
}));

// Set up EJS templating
app.set('view engine', 'ejs');

// Serve static files
app.use(express.static('public'));

// Body parser middleware to parse form data
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // To parse JSON bodies

// Initialize SQLite database
// Initialize SQLite database
const db = new sqlite3.Database('./db/chatdb.sqlite', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the SQLite database.');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
  db.run(`CREATE TABLE IF NOT EXISTS banned_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    reason TEXT,
    banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);  
});

function isAdmin(req, res, next) {
  const userId = req.session.userId;
  if (userId) {
    db.get(`SELECT role FROM users WHERE id = ?`, userId, (err, row) => {
      if (err) {
        console.error(err);
        res.sendStatus(500);
      }
      if (row && row.role === 'admin') {
        return next();
      }
      return res.sendStatus(403);
    });
  } else {
    return res.sendStatus(401);
  }
}

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  // sanitize shit ig some lengths for username would b good
  username = validator.trim(username);
  username= validator.escape(username);
  if (!validator.isLength(username, { min: 3, max: 20 })) {
    return res.redirect('/?error=invalidusername');
  }
  //password requirements no weak shit allowed
  const passwordRequirements = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
   // Check if the password meets the requirements
  if (!passwordRequirements.test(password)) {
    // If not, redirect and inform the user
    return res.redirect('/?error=invalidpassword');
  }

  // U like hash? 
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error(err);
      res.redirect('/');
    } else {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function (err) {
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



app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if the user exists in the users table
  db.get('SELECT id, password FROM users WHERE username = ?', [username], async (err, userRow) => {
    if (err) {
      console.error('Database error:', err);
      return res.redirect('/?error=databaseerror');
    }

    // If the user does not exist
    if (!userRow) {
      return res.redirect('/?error=usernotfound');
    }

    // Check if the user is banned
    db.get('SELECT user_id, reason FROM banned_users WHERE user_id = ?', [userRow.id], async (err, bannedRow) => {
      if (err) {
        console.error('Database error:', err);
        return res.redirect('/?error=databaseerror');
      }

      // If the user is banned
      if (bannedRow) {
        console.log(`User ${username} is banned for reason: ${bannedRow.reason}`);
        return res.redirect('/?error=banned');
      }

      // Check if the password is correct
      bcrypt.compare(password, userRow.password, (err, result) => {
        if (err) {
          console.error('Bcrypt error:', err);
          return res.redirect('/?error=bcrypterror');
        }

        // If the password is correct
        if (result) {
          req.session.userId = userRow.id;
          res.redirect('/chat');
        } else {
          // If the password is incorrect
          res.redirect('/?error=invalidpassword');
        }
      });
    });
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

// Admin routes
app.post('/ban-user', isAdmin, (req, res) => {
  const { userId, reason } = req.body;

  // Escape the reason for security
  const escapedReason = validator.escape(reason);

  // Insert into banned_users table
  db.run('INSERT INTO banned_users (user_id, reason) VALUES (?, ?)', [userId, escapedReason], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error banning user');
    } else {
      io.emit('banUser', { userId, reason: escapedReason });
      res.status(200).send('User banned');
    }
  });
});

app.post('/delete-message', isAdmin, (req, res) => {
  const { messageId } = req.body;

  // Delete the message from the messages table
  db.run('DELETE FROM messages WHERE id = ?', [messageId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error deleting message');
    } else {
      io.emit('deleteMessage', messageId);
      res.status(200).send('Message deleted');
    }
  });
});

io.on('connection', (socket) => {
  // Retrieve the userId from the socket's session
  const userId = socket.handshake.session.userId;
  const userSockets = {};
  
  let username;

  // Fetch the username from the database
  db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      console.error(err);
      return;
    }
    username = row ? row.username : null;
    console.log(`${username} connected`); // Log the username to the console

    // Broadcast to all sockets that a user has joined
    socket.broadcast.emit('userJoined', `${username} has joined the chat`);
  });

  // Fetch the last 10 messages from the database
  db.all('SELECT users.username, messages.message FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp DESC LIMIT 10', (err, rows) => {
    if (err) {
      console.error(err);
      return;
    }
    socket.emit('chatHistory', rows.reverse());
  });

  // ... other code ...

  socket.on('chatMessage', (msg) => {
    const parts = msg.split(' ');
    const command = parts[0];
    const targetUsername = parts[1];
  
    // Helper function to check admin privileges
    const checkAdminPrivileges = (callback) => {
      db.get('SELECT role FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
          console.error(err);
          return;
        }
        if (row && row.role === 'admin') {
          callback();
        } else {
          socket.emit('adminError', 'You do not have permission to perform this action.');
        }
      });
    };
  
    if (command === '/ban' && parts.length >= 3) {
      const reason = parts.slice(2).join(' ');
      checkAdminPrivileges(() => {
        // Perform the ban operation
        db.run('INSERT INTO banned_users (user_id, reason) SELECT id, ? FROM users WHERE username = ?', [reason, targetUsername], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          if (this.changes > 0) {
            console.log(`User ${targetUsername} has been banned for: ${reason}`);
            socket.broadcast.emit('userBanned', `User ${targetUsername} has been banned for: ${reason}`);
          } else {
            socket.emit('banError', `User ${targetUsername} does not exist or is already banned.`);
          }
        });
      });
    } else if (command === '/unban' && parts.length >= 2) {
      checkAdminPrivileges(() => {
        // Perform the unban operation
        db.run('DELETE FROM banned_users WHERE user_id = (SELECT id FROM users WHERE username = ?)', [targetUsername], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          if (this.changes > 0) {
            console.log(`User ${targetUsername} has been unbanned.`);
            socket.emit('unbanSuccess', `User ${targetUsername} has been unbanned.`);
          } else {
            socket.emit('unbanError', `User ${targetUsername} does not exist or is not banned.`);
          }
        });
      });
    } else {
      // Normal chat message handling
      db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
          console.error(err);
          return;
        }
        const username = row.username;
        db.run('INSERT INTO messages (user_id, message) VALUES (?, ?)', [userId, msg], function(err) {
          if (err) {
            console.error(err);
            return;
          }
          io.emit('chatMessage', { username, message: msg, timestamp: new Date() });
        });
      });
    }
  });
  
// ... rest of your server.js code ...


  socket.on('disconnect', () => {
    console.log(`${username} disconnected`); // Log the username to the console
  });
});


// Start the server
const PORT = process.env.PORT || 3000;
http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


