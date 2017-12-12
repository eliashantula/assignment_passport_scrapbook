const express = require("express");
const app = express();
const path = require("path");
const favicon = require("serve-favicon");
const User = require("./models/User");
const auth = require("./auth");
const expressSession = require("express-session");
const flash = require("express-flash");

// Local
app.locals.appName = "Passport Scrapbook";

// ----------------------------------------
// Passport
// ----------------------------------------
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
app.use(passport.initialize());
app.use(passport.session());

// ----------------------------------------
// Logging
// ----------------------------------------
const morgan = require("morgan");
const morganToolkit = require("morgan-toolkit")(morgan, {
  req: ["cookies" /*, 'signedCookies' */]
});

app.use(morganToolkit());

// ----------------------------------------
// Template Engine
// ----------------------------------------
const expressHandlebars = require("express-handlebars");
const helpers = require("./helpers");

const hbs = expressHandlebars.create({
  helpers: helpers,
  partialsDir: "views/",
  defaultLayout: "application"
});

app.engine("handlebars", hbs.engine);
app.set("view engine", "handlebars");

// ----------------------------------------
// Flash Messages
// ----------------------------------------
const flashMessages = require("express-flash-messages");
app.use(flashMessages());

// ----------------------------------------
// Body Parser
// ----------------------------------------
const bodyParser = require("body-parser");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ----------------------------------------
// Sessions/Cookies
// ----------------------------------------
const cookieParser = require("cookie-parser");

app.use(cookieParser());

// ----------------------------------------
// Express Session
// ----------------------------------------
app.use(flash());
app.use(
  expressSession({
    secret: process.env.secret || "keyboard cat",
    saveUninitialized: false,
    resave: false
  })
);

// ----------------------------------------
//middleware to connect to MongoDB via mongoose in your `app.js`
// ----------------------------------------
const mongoose = require("mongoose");
mongoose.connect("mongodb://localhost/assignment_passport_scrapbook");
app.use((req, res, next) => {
  if (mongoose.connection.readyState) {
    next();
  } else {
    require("./mongo")().then(() => next());
  }
});

// ----------------------------------------
// Public
// ----------------------------------------
app.use(express.static(`${__dirname}/public`));

// --------------------------------------
//Passport Strategies
//---------------------------------------
//---------------------
//**Local Strategy
//---------------------
passport.use(
  new LocalStrategy(function(email, password, done) {
    
    User.findOne({ email }, function(err, user) {
      if (err) return done(err);
      if (!user || !user.validPassword(password)) {
        return done(null, false, { message: "Invalid email/password" });
      }
      return done(null, user);
    });
  })
);

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//---------------------------
//**Facebook Strategy
//---------------------------
passport.use(
  new FacebookStrategy(
    {
      clientID: auth.facebookAuth.clientID,
      clientSecret: auth.facebookAuth.clientSecret,
      callbackURL: "http://localhost:3000/auth/facebook/callback"
    },
    function(accessToken, refreshToken, profile, done) {
      const facebookId = profile.id;
      const displayName = profile.displayName;

      console.log(profile);
      User.findOne({ facebookId }, function(err, user) {
        if (err) return done(err);

        if (!user) {
          // Create a new account if one doesn't exist
          user = new User({ facebookId, displayName });
          user.save((err, user) => {
            if (err) return done(err);
            done(null, user);
          });
        } else {
          // Otherwise, return the extant user.
          done(null, user);
        }
      });
    }
  )
);

// ----------------------------------------
//Routes
// ----------------------------------------
app.get("/", (req, res) => {
	

  if (req.session.passport && req.session.passport.user) {
    res.render("welcome/index", { currentUser: req.session.passport.user });
  } else {
    res.redirect("/login");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true
  })
);

app.post("/register", (req, res, next) => {
  const { email, password } = req.body;
  const user = new User({ email, password });
  user.save(err => {
   
    res.redirect("/login");
    // req.login(user, function(err) {
    //   if (err) {
    //     return next(err);
    //   }
    //   return res.redirect("/");
    // });
  });
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("login");
});

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", {
    successRedirect: "/",
    failureRedirect: "/login"
  })
);

// ----------------------------------------
// Server
// ----------------------------------------
const port = process.env.PORT || process.argv[2] || 3000;
const host = "localhost";

let args;
process.env.NODE_ENV === "production" ? (args = [port]) : (args = [port, host]);

args.push(() => {
  console.log(`Listening: http://${host}:${port}\n`);
});

if (require.main === module) {
  app.listen.apply(app, args);
}

// ----------------------------------------
// Error Handling
// ----------------------------------------
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err.stack) {
    err = err.stack;
  }
  res.status(500).render("errors/500", { error: err });
});

module.exports = app;
