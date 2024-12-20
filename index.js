import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth20";

const app = express();
const port = 3000;
const saltRounds = 10;

var userId = 0;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: "secrets",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 },
  })
);
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "authentication",
  password: "1234",
  port: 8080,
});
app.use(passport.initialize());
app.use(passport.session());
db.connect();

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/secrets");
  } else {
    res.render("home.ejs");
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/secrets", async (req, res) => {
  res.render("secrets.ejs", {
    userDetails: req.user,
  });

  // var userDetails = await checkUserDetails(userId);
  // if(userDetails.rows[0]){
  //   console.log(userDetails.rows[0]);

  // }
  // else{
  //   res.render("home.ejs",{userDetails:""});
  // }
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get('/submit',(req,res)=>{
   res.render('submit.ejs');
});
app.post('/submit',async (req,res)=>{

  if(req.isAuthenticated()){
    // res.json(req.user);
    if(req.user['user_id']){
      await db.query("update users_details set secrets=$1 where user_id=$2 ",[req.body.secret,req.user['user_id']]);

    }
    else{
      await db.query("update users_details set secrets=$1 where user_id=$2 ",[req.body.secret,req.user['id']]);
    }
    res.redirect('/');
  }
  console.log(req.body)

});
app.get("/userDetails", (req, res) => {});

app.get("/logout", (req, res) => {
  req.logout((err, done) => {
    if (err) {
    }
    res.redirect("/");
  });
});

app.post("/logout", (req, res) => {
  req.logOut((err, done) => {
    if (err) {
    }
    res.redirect("/");
  });
});

app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    successRedirect: "/secrets",
  }),
  function (req, res) {
    res.redirect("/");
  }
);

app.get(
  "/auth/google",
  passport.authenticate("google", {
    failureRedirect: "/login",
    successRedirect: "/secrets",
    scope: ["email", "profile"],
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          var result = await db.query(
            "INSERT INTO users (email, password,login_type) VALUES ($1, $2,$3) returning *",
            [email, hash, "normal"]
          );
          if (result.rows[0]) {
            await db.query(
              "INSERT INTO users_details (email_id, user_id,name) VALUES ($1, $2,$3)",
              [email, result.rows[0].id, email]
            );
          }

          res.redirect("/secrets");
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, result) => {
          if (err) {
            return cb(err, null);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
          } else {
            console.log("Hashed Password:", hash);
            var user = await db.query(
              "INSERT INTO users (email, password,login_type) VALUES ($1, $2,$3) returning *",
              [username, hash, "normal"]
            );
            if (user.rows[0]) {
              await db.query(
                "INSERT INTO users_details (email_id, user_id,name,picture) VALUES ($1, $2,$3,$4)",
                [user.rows[0].email, user.rows[0].id, user.rows[0].email, null]
              );
            }

            return cb(null, user);
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
  })
);
passport.use(
  new GoogleStrategy(
    {
      clientID:
        "272834398288-2pdsfr4fpjb4k0lmvjqlddpbug76pbv6.apps.googleusercontent.com",
      clientSecret: "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",
      callbackURL: "http://localhost:3000/auth/google",
      passReqToCallback: true,
    },
    async function (request, accessToken, refreshToken, user, cb) {
      console.log(user);
      try {
        const checkResult = await db.query(
          "SELECT * FROM users WHERE email = $1",
          [user._json.email]
        );

        if (checkResult.rows.length > 0) {
          var userDetails = await checkUserDetails(user._json.email);
          return cb(null, userDetails.rows[0]);
        } else {
          //hashing the password and saving it in the database
          bcrypt.hash("12345", saltRounds, async (err, hash) => {
            if (err) {
              console.error("Error hashing password:", err);
            } else {
              console.log("Hashed Password:", hash);
              var result = await db.query(
                "INSERT INTO users (email, password,login_type) VALUES ($1, $2,$3) returning *",
                [user._json.email, hash, "social"]
              );
              if (result.rows[0]) {
                await db.query(
                  "INSERT INTO users_details (email_id, user_id,name,picture) VALUES ($1, $2,$3,$4)",
                  [
                    user._json.email,
                    result.rows[0].id,
                    user._json.given_name,
                    user._json.picture,
                  ]
                );
              }
              var userDetails = await checkUserDetails(result.rows[0].email);
              return cb(null, userDetails.rows[0]);
            }
          });
        }
      } catch (err) {
        console.log(err);
      }
      return cb(null, user);
    }
  )
);
async function checkUserDetails(email) {
  var userDetails = await db.query(
    "select * from users join users_details on users_details.user_id = users.id where email = $1",
    [email]
  );
  return userDetails;
}
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
