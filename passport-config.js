const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

function initialize(passport, getUserByEmail, getUserById) {
    let user
    const authenticateUser = async (email, password, done) => {
        user = await getUserByEmail(email);
        
        if (user == null) {
            return done(null, false, { message: 'No user with that email.'});
        }
        try {
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Password incorrect.' })
            }
        } catch (err) {
            console.error('error: ', err);
            return done(err);
        }
    }
    passport.use(new LocalStrategy({
        usernameField: 'email',
    }, authenticateUser));
    // serialize to store in the session
    passport.serializeUser((user, done) => done(null, user._id));
    passport.deserializeUser((id, done) => {
        return done(null, getUserById(id));
    });
}

module.exports = initialize