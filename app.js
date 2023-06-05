require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const MicrosoftStrategy = require("passport-microsoft").Strategy;

const app = express();
const port = 3000;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(
  // This only a test cloud database. Please create your own database.
  "mongodb+srv://rayanbabur:rayan123@cluster0.nyma44h.mongodb.net/userDB"
);
const userSchema = new mongoose.Schema({
  googleId: String,
  googleUsername: String,
  googleEmail: String,
  googlePicture: String,
  microsoftId: String,
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, {
      id: user.id,
      username: user.googleUsername || user.microsoftUsername,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URI,
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);

      User.findOne({ googleId: profile.id }, function (err, foundUser) {
        if (!err) {
          if (foundUser) {
            return cb(null, foundUser);
          } else {
            //Create a new User
            const newUser = new User({
              // Add google scopes here
              googleId: profile.id,
              googleUsername: profile.displayName,
              googleEmail: profile.emails[0].value,
              googlePicture: profile.photos[0].value,
            });
            newUser.save(function (err) {
              if (!err) {
                return cb(null, newUser);
              }
            });
          }
        } else {
          console.log(err);
        }
      });
    }
  )
);
passport.use(
  new MicrosoftStrategy(
    {
      clientID: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      callbackURL: process.env.MICROSOFT_CALLBACK_URI,
      scope: ["user.read"],

      tenant: "common",

      authorizationURL:
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",

      tokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    },
    function (accessToken, refreshToken, profile, done) {
      // console.log(profile);
      User.findOne({ microsoftId: profile.id }, function (err, foundUser) {
        if (!err) {
          if (foundUser) {
            return cb(null, foundUser);
          } else {
            //Create a new User
            const newUser = new User({
              // Add microsoft scopes here
              microsoftId: profile.id,
            });
            newUser.save(function (err) {
              if (!err) {
                return cb(null, newUser);
              }
            });
          }
        } else {
          console.log(err);
        }
      });
    }
  )
);

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/home",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/home");
  }
);

app.get(
  "/auth/microsoft",
  passport.authenticate("microsoft", {
    prompt: "select_account",
  })
);

app.get(
  "/auth/microsoft/home",
  passport.authenticate("microsoft", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/home");
  }
);

app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("home");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
