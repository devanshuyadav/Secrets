# SECRETS | Authentication

## L1 - Username & Password Only
Simply storing Usernames and Password Strings in a MongoDb Collection

#### Risk: 
If database is compromised, all passwords would be accessible in Easily readable Strings.

---


## L2 - Mongoose-Encryption NPM Package
Using an NPM Package called [Mongoose-Encrption](https://www.npmjs.com/package/mongoose-encryption).

```const encrypt = require("mongoose-encryption"); ```

*(Make Sure to use a proper Mongoose Schema instead of a plain JS Object.)*

Take up an encrypting string, secret: <br>
```const secret = "Thisisourlittlesecret.";```<br>
and use the package as a mongoose plugin.

```userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });```

Now, all passwords will be encrypted using **AES-256-CBC**.

---
## L3 - MD5 Hashing
Using another NPM Package called [MD5](https://www.npmjs.com/package/md5).

Hashing is secure if implemented properly. A simple analogy of hashing is - 
- What are the factors of 12?
- there are more than one - 3\*4, 2\*6,...
- But what if we were to go the opposite way?
- what's 3*4? 12. That was Quick!

The basic idea is if we were to find one particular factor of a large number, it would take us some considerate amount of time to track the exact combination. But doing the opposite is just too naive!

***Hashing*** is based off the same principle. The passwords would be *hashed* and these hashes would be store in Mongoose-collection. Even if someone were to get access to the hashes, it would take them a lot to track-back the original string that was used to generate that particular hash. 

*But how would the original user login then?*

Simple. We would again generate a hash for the String used to Login and compare it to the hash store in Database that was created using String used for Sign-up. If they match, it's a successful login!

``` Const md5 = require('md5');```

When the user registers, pass it through the md5 hash function to store hash in db.

``` 
const newUser =  new User({
    email: req.body.username,
    password: req.body.password
    password: md5(req.body.password)
  }); 
```
and when the user tries to login, again pass it through md5 hash function and compare the generated hash with the one in database.

```
  const username = req.body.username;
  const password = md5(req.body.password);
  User.findOne({ email: username }, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        if (foundUser.password === password) {
          res.render("secrets");
        }
      }
    }
  });
  ```

#### Risk:
With advance computing, it is now possible to perform complex computations at a super high speed. One could still be able to figure out hash for a weak password through **fast processors**, or for easy *dictionary-based/guessable passwords* using **hash-tables**.

---

## L4 - Hashing with Salting
To deal with weak passwords like - *'qwerty', '123456', 'password' ...* We could have a random string and use that to hash the password string multiple times. 

This would make it almost impossible to track-back or wouldn't be worth the hacker's time to figure the password out.

We'll use an NPM Package called [bcrypt](https://www.npmjs.com/package/bcrypt), and also decide on a considerable amount of salting rounds. 
```
const bcrypt = require("bcrypt");
const saltRounds = 10;
```

Regarding the number of Salt Rounds, following is the amount of time it would take a 2GHZ core to track-back a 2^NumOfSaltRounds length of password,
```
rounds=8 : ~40 hashes/sec
rounds=9 : ~20 hashes/sec
rounds=10: ~10 hashes/sec
rounds=11: ~5  hashes/sec
rounds=12: 2-3 hashes/sec
rounds=13: ~1 sec/hash
rounds=14: ~1.5 sec/hash
rounds=15: ~3 sec/hash
rounds=25: ~1 hour/hash
rounds=31: 2-3 days/hash
```

<br>

After setting up *bcrypt*, we'll use **bcrypt.hash()** method to generate and store hash for a password after performing all rounds of salting.
```
bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser =  new User({
      email: req.body.username,
      password: hash
    });
    newUser.save(function(err){
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });
  ```

And when the user logs in, we'll use the **bcrypt.compare()** method to again generate a hash for x saltRounds and eventually compare it to the one in database.
```
User.findOne({email: username}, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function(err, result) {
          if (result === true) {
            res.render("secrets");
          }
        });
      }
    }
  });
  ```

---
## L5 - Cookies & Sessions
*Cookies*, or *Authentication Cookies* precisely, are useful to authenticate that a user has logged in and to identify what account they're using. If you don't have cookies on an app, one could easily go over to `http://localhost:3000/home-page` without having to login. This destroys the purpose of Login Systems and could be the Worst thing to do if the app is Hosted globally.

With Cookies, we can create sessions for our user that the browser can also store you the user when they get back to the site. This reduces the number of times the user has to login by a great factor.

```
app.get("/secrets", (req, res) => {
  // only if the user is signed in, allow them to access main page
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    // else send them back for logging in
    res.redirect("/login");
  }
});
```

We'll need some NPM Packages prior to implementing cookies - [express-session](https://www.npmjs.com/package/express-session), [passport](https://www.npmjs.com/package/passport), [passport-local](https://www.npmjs.com/package/passport-local) & [passport-local-mongoose](https://www.npmjs.com/package/passport-local-mongoose). *(that's a lot)*

Once we have the packages, we'll include them in our server.
```
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
```

\* Passport-local is a Utility inside the Passport NPM Package that doesn't need to be required specifically.

**For more detailed info on the following steps, refer to [PassportJS Docs](https://www.passportjs.org/docs/).** 

Create a session/strategy (currently we'll keep it for the local),
```
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
```

Then we'll initialize *Passport* and instruct it to use the LocalStrategy we defined above - 
```
app.use(passport.initialize());
app.use(passport.session());
```

Making sure that we have a proper MongoDB Schema and not just a JS Object, we can use the *Passport-Local-Mongoose* plugin onto the Schema.

Create a method to create serials for serializing and deserializing cookies for each session (note that we're using general method and not only for the local strategy)- 
```
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});
```

Now when a user registers, we'll pass it through **user.register()** & use the **passport.authenticate()** method to create & initialize a Local session for that user.

```
app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});
```

Now the user can browse through all routes made available to the kind of user, even switching through without logging out of their session.

And When the same user tries to login - 
```
app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });

});
```
We use Passport's **.login()** method and authenticate another session for them. Note that *.login()* is, in some ways, a subset of *.authenticate()*.

---

## L6 - Google OAuth2.0

Sigup-signin using third party authentication saves a lot on having to store user passwords and their security. Here, The Third party is responsible for storing and securing passwords. 

For Google OAuth, we use the Google Strategy in addition/place of the local one. Google authenticates the user, stores their credentials and gives back required details about the user like googleId, profile, email, and Google API data like YouTube, Gmail, Calenders, etc.

Proper Docmentation - http://www.passportjs.org/packages/passport-google-oauth2/

Google Strategy used - 
```
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      // Google+ deprecation fix - https://github.com/jaredhanson/passport-google-oauth2/pull/51
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      // implementing findOrCreate using findOrCreate plugin in 'mongoose-findOrCreate' npm package
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        
        return cb(err, user);
      });
    }
  )
);
```

Make these two routes available - 
```
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);
```
Rest of Authenticate while registering and logging in is similar to L5 Auth.

---