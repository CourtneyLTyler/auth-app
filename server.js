require('dotenv').config();

const express = require('express');
const mongo = require('mongodb').MongoClient;
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const override = require('method-override');

const initializePassport = require('./passport-config');
initializePassport.initialize(
    passport,
    email => users.find(user => user.email === email ),
    id => users.find(user => user.id === id)
);
const users = [];

app.set('view-engine', 'ejs');

const jwt = require('jsonwebtoken');

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

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name });
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
        // this is what we would send to the db
        // except wouldn't need id if using db, would be generated
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        })
        res.redirect('/login');
    } catch {
        res.redirect('/register');
    }
    console.log('users: ', users);
})

app.get('/posts', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name));
})

// app.post('/login', (req, res) => {
//     // authenticate user - separate video
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