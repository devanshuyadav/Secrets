//jshint esversion:6

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");

// L3
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// initialize a session, before connecting mongoose & after app is defined
app.use(
  session({
    secret: "My little secret.",
    resave: false,
    saveUninitialized: true,
  })
);

// initialize passport
app.use(passport.initialize());
// instruct passport to use the above initialized session
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

// conveinient method of encrypting in mongoose-encryption package
const secret = process.env.SECRET;

// // add package to userschema & only allow to encrypt the password field
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

// PASSPORT JS PLUGIN:
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

// from passportLocalMongoose docs
// serialize - to be able to create cookies
// deserialize - to be able to open/use cookies
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});
app.get("/secrets", (req, res) => {
  // only if the user is signed in, allow them to access main page
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    // else send them back for logging in
    res.redirect("/login");
  }
});

app.post("/register", (req, res) => {
  // use passportLocalMongoose's .register() method
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        // if authentication was successful
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  // use passportLocalMongoose's .logIn() method to log in
  req.login(user, (err) => {
    if (err) {
      console.log(err);
    } else {
      // if login was successful
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/logout", (req, res) => {
  // use passportLocalMongoose's .logout() to delete all session info of the logged in user
  req.logout();
  res.redirect("/");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
