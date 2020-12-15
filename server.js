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
let db, users;

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
    email => {
        return users.findOne({ email: email})
    },
    id => {
        return users.findOne({ _id: id })
    }
);
mongo.connect(dbUrl, (err, client) => {
    if (err) return err;
    db = client.db('authtestdb');
    users = db.collection('users');
})

const posts = [
    {
        username: 'Court',
        title: 'First Post'
    },
    {
        username: 'Jay',
        title: 'Second Post'
    }
]

app.get('/', checkAuthenticated, async (req, res) => {
    res.render('index.ejs');
})

app.get('/login', checkNotAuthenticated, (req, res) =>  {
    res.render('login.ejs');
})

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))

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

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name));
})

// app.post('/login', (req, res) => {
//     // authenticate user here
//     const username = req.body.username;
//     const user = { name: username };

//     const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
//     res.json({ accessToken: accessToken });
// })

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