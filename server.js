const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const socketIo = require('socket.io');
const http = require('http');
const multer = require('multer');
const path = require('path');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const { MongoClient, ServerApiVersion } = require('mongodb');
require('dotenv').config();

const app = express();

// Trust proxy for secure cookies in production
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
}

const server = http.createServer(app);
const io = socketIo(server);

// Connect to MongoDB
const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function connectToMongoDB() {
  try {
    // Connect the client to the server
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Successfully connected to MongoDB!");

    // Set up mongoose connection using the same URI
    await mongoose.connect(uri);
    console.log("Mongoose connected to MongoDB!");

    return true;
  } catch (err) {
    console.error("MongoDB connection error:", err);
    setTimeout(connectToMongoDB, 5000);
    return false;
  }
}

// Connect to MongoDB with retry
connectToMongoDB();

// Define Mongoose Schemas
const userSchema = new mongoose.Schema({
    googleId: String,
    email: String,
    displayName: String,
    photo: String,
    loginMethod: String,
    verificationCode: String,
    verificationCodeExpires: Number
});

const groupSchema = new mongoose.Schema({
    name: String,
    members: [{ email: String, displayName: String }],
    messages: [{ user: String, email: String, msg: String, timestamp: Date }],
    ownerId: String
});

const friendRequestSchema = new mongoose.Schema({
    from: String,
    to: String
});

const friendshipSchema = new mongoose.Schema({
    user1: String,
    user2: String
});

const User = mongoose.model('User', userSchema);
const Group = mongoose.model('Group', groupSchema);
const FriendRequest = mongoose.model('FriendRequest', friendRequestSchema);
const Friendship = mongoose.model('Friendship', friendshipSchema);

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middleware
app.use(express.static('public'));
app.use(express.json());

// Session middleware with MongoDB store
const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        ttl: 60 * 60 * 24 * 7, // 1 week
        autoRemove: 'native'
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        sameSite: 'none', // Allow cross-site cookies for OAuth
        maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
        domain: process.env.NODE_ENV === 'production' ? '.onrender.com' : undefined
    }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

// Share session with Socket.IO
io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

// Set view engine
app.set('view engine', 'ejs');

// Passport setup
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
        user = new User({
            googleId: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value,
            photo: profile.photos[0].value,
            loginMethod: 'google'
        });
        await user.save();
    }
    return done(null, user);
}));

passport.serializeUser((user, done) => {
    done(null, user.googleId || user.email);
});

passport.deserializeUser(async (id, done) => {
    const user = await User.findOne({ $or: [{ googleId: id }, { email: id }] });
    done(null, user);
});

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: 'public/uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Routes
app.get('/', async (req, res) => {
    console.log('Root route accessed');
    console.log('Session:', req.session);
    console.log('Is authenticated:', req.isAuthenticated());
    console.log('Email verified:', req.session.emailVerified);

    if (req.isAuthenticated() || req.session.emailVerified) {
        console.log('User is authenticated or email verified');
        try {
            const user = req.user || (await User.findOne({ email: req.session.emailVerified }));
            console.log('User found:', user ? user.email : 'No user');

            const userFriendships = await Friendship.find({
                $or: [{ user1: user.googleId || user.email }, { user2: user.googleId || user.email }]
            });
            const friends = await Promise.all(userFriendships.map(async f => {
                const friendId = f.user1 === (user.googleId || user.email) ? f.user2 : f.user1;
                return await User.findOne({ $or: [{ googleId: friendId }, { email: friendId }] });
            })).then(results => results.filter(f => f));
            const userFriendRequests = await FriendRequest.find({ to: user.email });
            const users = await User.find();

            console.log('Rendering index page');
            res.render('index', { user, friends, friendRequests: userFriendRequests, users });
        } catch (err) {
            console.error('Error in root route:', err);
            res.status(500).send('An error occurred');
        }
    } else {
        console.log('User not authenticated, rendering sign-in page');
        res.render('sign-in');
    }
});

app.get('/auth/google', (req, res, next) => {
    console.log('Starting Google authentication...');
    passport.authenticate('google', {
        scope: ['profile', 'email']
    })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
    console.log('Google callback received...');
    passport.authenticate('google', (err, user, info) => {
        console.log('Auth result:', { err, user: user ? 'User found' : 'No user', info });
        if (err) {
            console.error('Authentication error:', err);
            return res.redirect('/');
        }
        if (!user) {
            console.error('Authentication failed:', info);
            return res.redirect('/');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('Login error:', err);
                return res.redirect('/');
            }
            console.log('User authenticated successfully');
            return res.redirect('/');
        });
    })(req, res, next);
});

app.post('/sign-in-email', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ error: 'Email is required.' });
    }

    let user = await User.findOne({ email });
    if (!user) {
        user = new User({
            email: email,
            displayName: email.split('@')[0],
            photo: null,
            loginMethod: 'email',
            verificationCode: null,
            verificationCodeExpires: null
        });
        await user.save();
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    user.verificationCode = verificationCode;
    user.verificationCodeExpires = Date.now() + 15 * 60 * 1000; // 15 minutes expiry
    await user.save();

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Massed - Your Verification Code',
        text: `Your verification code for Massed is: ${verificationCode}\n\nThis code will expire in 15 minutes.`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Verification email sent to ${email}: ${verificationCode}`);
    } catch (err) {
        console.error('Error sending verification email:', err);
        return res.status(500).json({ error: 'Error sending verification email.' });
    }

    req.session.emailToVerify = email;
    res.json({ message: 'Verification code sent to your email. If you don’t see it in your inbox, please check your spam folder.' });
});

app.get('/verify-email', (req, res) => {
    const email = req.query.email || req.session.emailToVerify;
    if (!email) {
        return res.redirect('/');
    }
    res.render('verify-email', { email });
});

app.post('/verify-email', async (req, res) => {
    const { email, code } = req.body;
    const user = await User.findOne({ email });

    if (!user || user.verificationCode !== code || Date.now() > user.verificationCodeExpires) {
        return res.status(400).json({ error: 'Invalid or expired verification code.' });
    }

    user.verificationCode = null;
    user.verificationCodeExpires = null;
    await user.save();

    req.session.emailVerified = email;
    res.json({ message: 'Email verified successfully.' });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    req.logout(() => {
        res.redirect('/');
    });
});

app.post('/add-friend', async (req, res) => {
    const { email } = req.body;
    const user = req.user || (await User.findOne({ email: req.session.emailVerified }));
    const friend = await User.findOne({ email });

    if (!friend) {
        return res.status(404).json({ error: 'User not found.' });
    }

    if (friend.email === user.email) {
        return res.status(400).json({ error: 'You cannot add yourself as a friend.' });
    }

    const existingRequest = await FriendRequest.findOne({ from: user.googleId || user.email, to: friend.email });
    if (existingRequest) {
        return res.status(400).json({ error: 'Friend request already sent.' });
    }

    const existingFriendship = await Friendship.findOne({
        $or: [
            { user1: user.googleId || user.email, user2: friend.googleId || friend.email },
            { user1: friend.googleId || friend.email, user2: user.googleId || user.email }
        ]
    });
    if (existingFriendship) {
        return res.status(400).json({ error: 'You are already friends.' });
    }

    const friendRequest = new FriendRequest({
        from: user.googleId || user.email,
        to: friend.email
    });
    await friendRequest.save();

    io.emit('friendRequest', {
        from: user.googleId || user.email,
        to: friend.email,
        fromUser: user
    });

    res.json({ message: 'Friend request sent.' });
});

app.post('/accept-friend', async (req, res) => {
    const { fromId } = req.body;
    const user = req.user || (await User.findOne({ email: req.session.emailVerified }));

    const friendRequest = await FriendRequest.findOne({ from: fromId, to: user.email });
    if (!friendRequest) {
        return res.status(404).json({ error: 'Friend request not found.' });
    }

    await FriendRequest.deleteOne({ from: fromId, to: user.email });

    const friendship = new Friendship({
        user1: fromId,
        user2: user.googleId || user.email
    });
    await friendship.save();

    io.emit('friendshipUpdate', { userId: user.googleId || user.email });
    io.emit('friendshipUpdate', { userId: fromId });

    res.json({ message: 'Friend request accepted.' });
});

app.post('/decline-friend', async (req, res) => {
    const { fromId } = req.body;
    const user = req.user || (await User.findOne({ email: req.session.emailVerified }));

    const friendRequest = await FriendRequest.findOne({ from: fromId, to: user.email });
    if (!friendRequest) {
        return res.status(404).json({ error: 'Friend request not found.' });
    }

    await FriendRequest.deleteOne({ from: fromId, to: user.email });
    res.json({ message: 'Friend request declined.' });
});

app.post('/remove-friend', async (req, res) => {
    const { friendId } = req.body;
    const user = req.user || (await User.findOne({ email: req.session.emailVerified }));

    const friendship = await Friendship.findOne({
        $or: [
            { user1: user.googleId || user.email, user2: friendId },
            { user1: friendId, user2: user.googleId || user.email }
        ]
    });

    if (!friendship) {
        return res.status(404).json({ error: 'Friendship not found.' });
    }

    await Friendship.deleteOne({
        $or: [
            { user1: user.googleId || user.email, user2: friendId },
            { user1: friendId, user2: user.googleId || user.email }
        ]
    });

    io.emit('friendshipUpdate', { userId: user.googleId || user.email });
    io.emit('friendshipUpdate', { userId: friendId });

    res.json({ message: 'Friend removed.' });
});

app.get('/get-friends', async (req, res) => {
    const user = req.user || (await User.findOne({ email: req.session.emailVerified }));
    const userFriendships = await Friendship.find({
        $or: [{ user1: user.googleId || user.email }, { user2: user.googleId || user.email }]
    });
    const friends = await Promise.all(userFriendships.map(async f => {
        const friendId = f.user1 === (user.googleId || user.email) ? f.user2 : f.user1;
        return await User.findOne({ $or: [{ googleId: friendId }, { email: friendId }] });
    })).then(results => results.filter(f => f));
    res.json(friends);
});

app.get('/get-user', async (req, res) => {
    const { email } = req.query;
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ error: 'User not found.' });
    }
    res.json(user);
});

app.post('/update-name', async (req, res) => {
    const { displayName } = req.body;
    const user = req.user || (await User.findOne({ email: req.session.emailVerified }));

    if (!displayName) {
        return res.status(400).json({ error: 'Display name is required.' });
    }

    const oldDisplayName = user.displayName;
    user.displayName = displayName;
    await user.save();

    io.emit('userUpdated', {
        googleId: user.googleId,
        email: user.email,
        displayName: user.displayName,
        photo: user.photo
    });

    io.emit('messagesUpdated', {
        oldDisplayName,
        newDisplayName: displayName
    });

    res.json({ message: 'Display name updated.' });
});

app.post('/update-profile-picture', upload.single('profilePicture'), async (req, res) => {
    const user = req.user || (await User.findOne({ email: req.session.emailVerified }));

    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded.' });
    }

    user.photo = `/uploads/${req.file.filename}`;
    await user.save();

    io.emit('userUpdated', {
        googleId: user.googleId,
        email: user.email,
        displayName: user.displayName,
        photo: user.photo
    });

    res.json({ message: 'Profile picture updated.' });
});

// Socket.io
io.on('connection', async (socket) => {
    const session = socket.request.session;
    const userId = session.passport?.user || session.emailVerified;
    const user = await User.findOne({ $or: [{ googleId: userId }, { email: userId }] });

    if (user) {
        const groups = await Group.find({ 'members.email': user.email });
        socket.emit('groupList', groups);
    }

    socket.on('createGroup', async ({ groupName, memberEmails }, callback) => {
        const session = socket.request.session;
        const userId = session.passport?.user || session.emailVerified;
        const user = await User.findOne({ $or: [{ googleId: userId }, { email: userId }] });

        if (!user) {
            return callback({ error: 'User not found.' });
        }

        const members = await Promise.all(memberEmails.map(async email => {
            const member = await User.findOne({ email });
            return member ? { email: member.email, displayName: member.displayName } : null;
        })).then(results => results.filter(m => m));

        members.push({ email: user.email, displayName: user.displayName });

        const group = new Group({
            name: groupName,
            members,
            messages: [],
            ownerId: user.googleId || user.email
        });

        await group.save();

        const allUsers = await User.find();
        for (const u of allUsers) {
            const userGroups = await Group.find({ 'members.email': u.email });
            io.to(u.googleId || u.email).emit('groupList', userGroups);
        }

        callback({ success: true });
    });

    socket.on('joinGroup', async (groupId) => {
        const session = socket.request.session;
        const userId = session.passport?.user || session.emailVerified;
        const user = await User.findOne({ $or: [{ googleId: userId }, { email: userId }] });

        const group = await Group.findOne({ _id: groupId, 'members.email': user.email });
        if (group) {
            socket.join(groupId);
            // Sort messages by timestamp before sending
            group.messages.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
            socket.emit('groupMembers', {
                groupId: group._id,
                group: group.name,
                members: group.members,
                messages: group.messages,
                ownerId: group.ownerId
            });
        } else {
            socket.emit('groupMembers', { error: 'You are not a member of this group.' });
        }
    });

    socket.on('leaveGroup', (groupId) => {
        socket.leave(groupId);
    });

    socket.on('message', async (data) => {
        const group = await Group.findOne({ _id: data.groupId });
        if (group) {
            const message = {
                user: data.user,
                email: data.email,
                msg: data.msg,
                timestamp: new Date() // Ensure timestamp is a Date object
            };
            console.log(`Server: New message from ${data.user} at ${message.timestamp} (${message.timestamp.getTime()})`);
            group.messages.push(message);
            await group.save();
            // Sort messages after adding a new one
            group.messages.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
            io.to(data.groupId).emit('message', {
                groupId: data.groupId,
                user: data.user,
                email: data.email,
                msg: data.msg,
                timestamp: message.timestamp // Send the full Date object
            });
        }
    });

    socket.on('deleteGroup', async (groupId, callback) => {
        const session = socket.request.session;
        const userId = session.passport?.user || session.emailVerified;
        const user = await User.findOne({ $or: [{ googleId: userId }, { email: userId }] });
        const group = await Group.findOne({ _id: groupId });

        if (!group) {
            return callback({ error: 'Group not found.' });
        }

        if (group.ownerId !== (user.googleId || user.email)) {
            return callback({ error: 'Only the group owner can delete the group.' });
        }

        await Group.deleteOne({ _id: groupId });

        const allUsers = await User.find();
        for (const u of allUsers) {
            const userGroups = await Group.find({ 'members.email': u.email });
            io.to(u.googleId || u.email).emit('groupList', userGroups);
        }

        io.emit('groupDeleted', groupId);
        callback({ success: true });
    });

    socket.on('mentionNotification', async (data) => {
        const { mentionedEmail, sender, message, groupName } = data;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: mentionedEmail,
            subject: `Massed - You were mentioned in ${groupName}`,
            text: `${sender} mentioned you in ${groupName}:\n\n"${message}"\n\nLog in to Massed to view the message: ${process.env.APP_URL}`
        };

        try {
            await transporter.sendMail(mailOptions);
            console.log(`Mention notification email sent to ${mentionedEmail}`);
        } catch (err) {
            console.error('Error sending mention notification email:', err);
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', userId);
    });

    if (user) {
        socket.join(user.googleId || user.email);
    }
});

const PORT = process.env.PORT || 3002;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});