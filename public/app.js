const express = require('express')
const session = require('express-session')
const hbs = require('express-handlebars')
const mongoose = require('mongoose')
const passport = require('passport')
const localStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')
const bodyParser = require('body-parser')
const ejs = require('ejs')
const path = require('path')
const flash = require('connect-flash')

mongoose.connect(
  'mongodb://localhost:27017/node-auth-CarMS',
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => console.log('connected to DB')
)
const app = express()

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
})

const User = mongoose.model('user', userSchema)
const newUser = new User({
  name: 'yox',
  email: 'yo@1.com',
  password: 'yoyoyo',
})

newUser.save(() => console.log(newUser.name))

//Middleware
//app.engine("hbs", hbs({extname: ".hbs"}));
app.set('view engine', 'ejs')
app.use('/', express.static(path.join(__dirname, 'public')))
app.use(
  session({
    secret: 'jawara',
    resave: false,
    saveUninitialized: true,
  })
)
app.use(express.urlencoded({ extended: true }))
app.use(bodyParser.urlencoded({ extended: true }))
//app.use(bodyParser.json());
app.use(express.json())

//app.use(express.cookieParser('keyboard cat'));
//app.use(express.session({ cookie: { maxAge: 60000 }}));
app.use(flash())

/*Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user.id);
})

passport.deserializeUser((id, done) =>{
    User.findById(id, (err, user) =>{
        done(err, user);
    });
})

passport.use(new localStrategy((username, password, done) => {
    User.findOne({username: username}, (err, user) => {
        if (err) {
            return done(err);
        }
        if (!user){
            return done(null, false, {message: "Incorrect username"});
        }

        bcrypt.compare(password, user.password, (err, res) =>{
            if (err) {
                return done(err);
            }
            if (res === false){
                return done(null, false, {message: "password incorrect"})
            }

            return done(null, user);
        })
    });
}));

/*function isLoggedIn(req, res, next){
    if (req.isAuthenticated()){
        return next();
    } 
    res.redirect("/login");
}

function isLoggedOut(req, res, next){
    if (!req.isAuthenticated()){
        return next();
    } 
    res.redirect("/");
}*/

//ROUTES
app.get(
  '/',
  /*isLoggedIn,*/ (req, res) => {
    req.flash('info', 'hello')
    res.render('homepage')
  }
)

app.get(
  '/login',
  /*isLoggedOut,*/ (req, res) => {
    /*const response = {
        title: "Login",
        error: req.query.error
    }*/

    res.render('login' /*response*/)
  }
)

app.get('/register', (req, res) => {
  res.render('register')
})

app.get('/homepage', (req, res) => {
  res.render('homepage')
})

app.get('/billing', (req, res) => {
  res.render('billing')
})

app.get('/kanban', (req, res) => {
  res.render('kanban')
})

app.get('/profile', (req, res) => {
  res.render('profile')
})

app.get('/test', (req, res) => {
  res.json({
    status: 'ok',
  })
})

/*app.post("/login", passport.authenticate("local",{
    successRedirect: "/",
    failureRedirect: "/login?error=true"
}));*/

/*app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {return next(err);}
        res.redirect("/");
    });
});*/

//Authenticate new/old users
app.post('/register', async (req, res) => {
  console.log(req.body.newPassword)
  const exists = await User.exists({ email: req.body.newEmail })

  if (exists) {
    res.redirect('/login')
    return
  }

  /*bcrypt.genSalt(10, (err, salt) => {
        if (err){return next (err);}
        bcrypt.hash(req.body.registerPassword, salt, (err, hash) =>{
            if (err){return next(err)}
        });      
    }); */
  console.log(req.body.newPassword)
  const user = new User({
    name: req.body.name,
    email: req.body.newEmail,
    password: req.body.newPassword,
  })

  console.log(user.password)

  await user.save((err) => {
    if (err) return console.log('ERROR: ', err)
    res.render('homepage')
  })
})

//login new users
app.post('/login', (req, res) => {
  const userEmail = req.body.email
  const userPassword = req.body.password

  User.findOne({ email: userEmail }, (err, foundUser) => {
    if (err) {
      return console.log(err)
    }
    if (!foundUser || foundUser.password !== userPassword) {
      return res.status(404).send({
        message: 'user not found',
        status: 'error',
      })
    }
    delete foundUser.password
    res.send(foundUser)
    console.log(req.body)
  })
})

/*   });
});*/

/*Set up Admin User
app.get("/user", async (req, res) => {
    const exists = await User.exists({email: "admin@gmail.com"});

    if(exists){
        res.redirect("/login");
        return;
    }

    bcrypt.genSalt(10, (err, salt) =>{
        if (err){return next (err);}
        console.log(err);
        bcrypt.hash("coventryy", salt, (err, hash) =>{
            if (err){return next(err)}
            console.log(err);

            const newAdmin = new User({
                
                name: "Admin",
                email: "admin@gmail.com",
                password: hash
            });

            newAdmin.save();

            res.redirect("/login");
        });
    });
});*/

/*app.use("/", express.static(path.join(__dirname, "public")))
app.set("view engine", "ejs");
app.use(bodyParser.json());

app.post("/api/register", async(req, res) => {
    console.log(req.body);
    res.json({statis : "ok"});
})

app.get("/", (req, res) => {
    res.render("login");
})


app.listen(3000, function(){
    console.log("Server started on port 3000...");
})*/

app.listen(3000, () => {
  console.log('Server running on port 3000')
})
