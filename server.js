require('dotenv').config();

const express = require('express');
const mongo = require('mongodb').MongoClient;
const dbUrl = 'mongodb://localhost:27017';
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const override = require('method-override');
const jwt = require('jsonwebtoken');
let db, users, posts;

const initializePassport = require('./passport-config');

app.set('view-engine', 'ejs');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize());
app.use(passport.session());
app.use(override('_method'));


initializePassport(
    passport,
    email => users.findOne({ email: email}),
    id => users.findOne({ _id: id })
);
mongo.connect(dbUrl, (err, client) => {
    if (err) return err;
    db = client.db('authtestdb');
    users = db.collection('users');
    posts = db.collection('posts');
})

app.get('/', checkAuthenticated, async (req, res) => {
    res.render('index.ejs');
})

app.get('/login', checkNotAuthenticated, (req, res) =>  {
    res.render('login.ejs');
})

app.post('/login', passport.authenticate('local'), (req, res) => {
    if (req.user == null) {
        res.redirect('/login)')
        return
    }
    if (req.user) {
        const accessToken = jwt.sign(req.user, process.env.ACCESS_TOKEN_SECRET);
        users.updateOne(
            { email: req.user.email },
            {
                $set: { "token": accessToken }
            }
        )
        res.redirect('/');
    }
})

app.get('/register', (req, res) =>  {
    res.render('register.ejs');
})

app.post('/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = {
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        }
        users.insertOne(user);
        return res.redirect('/login');
    } catch {
        res.redirect('/register');
    }
})

app.post('/posts', (req, res) => {
    const post = req.body.post;
    const email = req.body.email;
    posts.insertOne({
        post: post,
        email: email
    });
    res.send()
})

app.get('/posts', authenticateToken, async (req, res) => {
    const sendPosts = await posts.find({ email: req.user.email }).toArray();
    res.send(sendPosts);
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // && means if authHeader exists, do the following
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    })
}

app.delete('/logout', (req, res) => {
    // this is from passport - clears sessions and logs user out
    req.logOut();
    res.redirect('/login');
})

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    } 
    res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    } 
    next()
}

app.listen(3333);