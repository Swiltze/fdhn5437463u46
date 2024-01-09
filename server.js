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
const sessionMiddleware= session({
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
  if (req.session.role === 'admin') {
    next();
  } else {
    res.status(403).send('Access Denied Idiot');
  }
};


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
      console.error(err)
      res.redirect('/');
    } else {
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
    if (err) {
      res.redirect('/');
        } else {
          req.session.userId = this.lastID;
          res.redirect('/chat');
        });
      });
  });


app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if user exists in user table
  db.get('SELECT id, password FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) {
      console.error(err);
      return res.redirect('/');
    // who the fuck r u?   
    } if (!row) {
      return res.redirect('/?error=nonexistantuser');
    }
  // do the user exist? yes? check if the fucker is banned  
  db.get('SELECT user_id FROM banned_users WHERE user_id = ?', [row.id], async (err, bannedRow) => {
    if (err) {
      console.error(err);
      return res.redirect('/');
    }
    //are they banned?    
    if(bannedRow) {
      console.log(`${username} is banned for ${bannedRow.reason}`);
      return res.redirect('/banned');
    }
    // no? good boy!! check if the password is correct
    bcrypt.compare(password, row.password, (err, result) => {
      if (err) {
        console.error(err);
        return res.redirect('/');
      }
      //yes?
      if (result) {
        req.session.userId = row.id;
        res.redirect('/chat');
      } else {
        //nooooooo!!!
        res.redirect('/?error=wrongpassword');
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

app.post('/ban-user', isAdmin, (req, res) => {
  const { userId } = req.body;
  let { reason } = req.body;

  reason = validator.escape(reason);

  db.run('INSERT INTO banned_users (user_id, reason) VALUES (?, ?)', [userId, reason], (err) => {
    if (err) {
      console.error(err);
      return res.sendStatus(500).send('Error banning user');
    } else {
      io.emit('banUser', userId);
      res.status(200).send('User banned');
    }
    res.sendStatus(200);
  });
});

app.post('/delete-message', isAdmin, (req, res) => {
  const messageId = req.body.messageId;
  db.run('DELETE FROM messages WHERE id = ?', [messageId], (err) => {
    if (err) {
      console.error(err);
      return res.sendStatus(500).send('Error deleting message');
    } else {
      io.emiter('deleteMessage', messageId);
      res.status(200).send('Message deleted');
    }
  });
});


const userSockets = {};
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
  // Check if the message is a ban command
  if (msg.startsWith('/ban ')) {
    // Split the message to extract the username and reason
    const parts = msg.split(' ');
    if (parts.length >= 3) {
      const targetUsername = parts[1];
      const reason = parts.slice(2).join(' ');

      // Check if the user has admin privileges
      db.get('SELECT role FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
          console.error(err);
          return;
        }
        if (row && row.role === 'admin') {
          // Perform the ban operation
          db.run('INSERT INTO banned_users (user_id, reason) SELECT id, ? FROM users WHERE username = ?', [reason, targetUsername], function(err) {
            if (err) {
              console.error(err);
              return;
            }
            if (this.changes > 0) {
              console.log(`User ${targetUsername} has been banned by ${username} for: ${reason}`);
              // tell everyone they got banned so they can be shunned. 
              socket.broadcast.emit('userBanned', `User ${targetUsername} because they ${reason}`);
            } else {
              // Emit a message if the target user does not exist
              socket.emit('banError', `User ${targetUsername} does not exist or is already banned.`);
            }
          });
        } else {
          // Emit a message if the user does not have admin privileges
          socket.emit('banError', 'You do not have permission to ban users.');
        }
      });
    } else {
      // Emit a message if the command format is incorrect
      socket.emit('banError', 'Usage: /ban username reason');
    }
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
