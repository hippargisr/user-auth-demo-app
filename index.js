const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');
const socketIO = require('socket.io');
const mongoose = require('mongoose');

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb+srv://sunil:sunil@cluster0.njjfe5u.mongodb.net/user-auth-app?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User schema
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const User = mongoose.model('User', UserSchema);

// Passport configuration
passport.use(
  new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return done(null, false, { message: 'Incorrect email' });
      }
      if (user.password !== password) {
        return done(null, false, { message: 'Incorrect password' });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    jwt.verify(token, 'secret_key', (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Routes
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(passport.initialize());

app.get("/", (req, res)=>{
  res.send("HELLO");
})

app.post('/login', passport.authenticate('local', { session: false }), (req, res) => {
  const { user } = req;
  console.log(user);
  const token = jwt.sign(user.toJSON(), 'secret_key');
  res.json({ token });
});

app.get('/protected', authenticateToken, (req, res) => {
  res.send('You have access to this protected route');
});

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists' });
    }
    const newUser = new User({ email, password });
    await newUser.save();
    res.json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

const server = app.listen(3000, () => {
  console.log('Server started on port 3000');
});
const io = socketIO(server);

// Socket.io configuration
io.on('connection', (socket) => {
  console.log('A user connected');

  socket.on('clientMessage', (message) => {
    console.log('Received message from client:', message);
    socket.emit('serverMessage', 'Message received');
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});
