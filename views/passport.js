const LocalStrategy = require('passport-local').Strategy;
const { pool }= require('../db');
const bcrypt= require('bcrypt');


function initialize(passport) {
    const authenticateUser= (email, passport, done) => {
        pool.query( 
            `SELECT * FROM users WHERE email = $1`,
            [email],
            (error, result) => {
                if (error) {
                    throw error;
                }
                if(result.row.length > 0 ) {
                    const user = result.row[0];

                    bcrypt.compare(password, user.password, (err, isMacht)=> {
                        if(err) {
                            throw err
                        }
                        if (isMacht){
                            return done(null, user);
                        }else {
                            return done(null, false, {message:'password is not correct'});
                        }
                    });
                }else {
                    return done(null, false, {message: 'email is not registered'})
                }
            }
        );
    };

    passport.use(
        new LocalStrategy({
            usernameField: 'email',
            passportField: 'password'
        },
        authenticateUser
        )
    );

    passport.serializeUser((user, done) => done(null, user.id));
    
    passport.deserializeUser((id, done) => {
        pool.query(
            `SELECT * FROM users WHERE id = $1`, [id], (err, result)=>{
                if(err) {
                    throw err
                }
                return done(null, result.row[0]);
            })
    })

}

module.exports = initialize;