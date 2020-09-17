const express = require("express");
const app = express();
const {pool} = require('./db'); 
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport= require('passport');

const initializePassport =require('./views/passport')

initializePassport(passport);

const PORT = process.env.PORT || 4000

// Cosas de libreria que necesito
app.set("view engine", "ejs"); //Para mostrar en render()
app.use(express.urlencoded({extended: false})); //Para codificar el password
app.use(session({
    secret: 'secret', 
    resave: false,
    saveUninitialized: false,
}))  // para guardar la informacion en una sesion local LocalStrategy
app.use(flash()); //Para enviar mensajes en la pag
app.use(passport.initialize()); // Para inicializar el proceso de autenticacion 
app.use(passport.session()); // para crear una sesion local


// Rutas o request que hago para mostrar en el front 
app.get('/', (req,res ) => {
    res.render('index')
});

app.get('/users/register' ,checkAuthenticated, (req,res ) => {
    res.render('register')
});

app.get('/users/login', checkAuthenticated, (req,res ) => {
    res.render('login')
});

app.get('/users/profile', checkNotAuthenticated,  (req,res ) => {
    res.render('profile', {user: req.user.name});
})

app.get('/users/logout', (req,res) => {
    req.logOut();
    req.flash('Success_msg', 'You have logged out');
    res.redirect('/users/login');
})


//Seteo la contraseña, hasheo y guardo la  info de registro
app.post('/users/register', async (req,res ) => {
    let {name,email,password} = req.body;  
   
    //console.log(name,email,password)
    
    let errors = [];

    if (!name || !email || !password) {
        errors.push({message: 'Please enter all fields'})
    }
    if (password.length < 6 ){
        errors.push({message: 'Password should be at least 12 characters'})
    }
    if (errors.length > 0) {
        res.render('register' , {errors})
    }else {
        //Form validation has passed

        let hashPassword = await bcrypt.hash(password, 10);
        //console.log(hashPassword);
    
        pool.query(
            `SELECT * FROM users
            WHERE  email = $1, `,
            {email},
            (error,result) => {
                if (error) {
                    throw error;
                }
                //console.log(result.rows);

                if (result.rowCount.length > 0) {
                    errors.push({message: 'Email alreday register'})
                    res.render('register', {errors})
                } else {
                    pool.query(
                        `INSERT INTO users (name, email, password)
                         VALUE ($1, $2, $3)
                         RETURNING id,password`,
                         [name, email, hashPassword],
                         (error,result) => {
                             if (error) {
                                 throw error;
                             }
                             req.flash('success_msg', "You are now Registered")
                             res.redirect('/users/login');
                        }
                    )
                }
            }
        )
    
    
    }
})

app.post('/users/login', (passport.authenticate('local', {
    successRedirect:'/users/profile',
    failureRedirect: '/users/login',
    failureFlash: true
})))

//Middleware de autenticacion paara proteger las rutas
function checkAuthenticated(req,res,next) {
    if (req.isAuthenticated()) {
        return res.redirect('/users/profile');
    }
    next();
}

function checkNotAuthenticated(req,res,next){
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect('users/login');
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
});
