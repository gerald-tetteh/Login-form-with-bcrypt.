import express from "express";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import flash from "connect-flash";
import session from "express-session";

const app = express();
let globaluser = null;
let globaltoken = null;
let users = [];
dotenv.config();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_KEY,
  resave: false,
  saveUninitialized: false
}));
app.use(flash());
app.use((req, res, next) => {
  res.locals.wrongCredentials = req.flash("credentials");
  res.locals.mustLogin = req.flash("login");
  next();
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/index-page", checkAuth, (req, res) => {
  console.log(globaluser);
  console.log(globaltoken);
  res.render("index");
});

app.post("/register", async (req, res) => {
  const hashPassword = await bcrypt.hash(req.body.data["password"], 10);
  const token = generateToken(req.body.data["username"]);
  const user = {
    username: req.body.data["username"],
    password: hashPassword
  };
  users.push(user);
  globaluser = user;
  globaltoken = token;
  console.log(user);
  res.redirect("/index-page");
});

app.get("/logout", (req, res) => {
  globaltoken = null;
  globaluser = null;
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const userData = req.body.data;
  const user = users.find(user => user.username === userData["username"]);
  if (user === null) {
    req.flash("credentials", "Wrong username or password");
    return res.redirect("/login");
  }
  try {
    if (await bcrypt.compare(userData["password"], user.password)) {
      const token = generateToken(req.body.data["username"]);
      globaluser = user;
      globaltoken = token;
      res.redirect("/index-page");
    } else {
      req.flash("credentials", "Wrong username or password");
      res.redirect("/login");
    }
  } catch (error) {
    req.flash("credentials", "Wrong username or password");
    res.redirect("/login");
  }
});

function generateToken(username) {
  return jwt.sign(username, process.env.JWT_TOKEN);
}

function checkAuth(req, res, next) {
  if (globaltoken == null) {
    req.flash("login", "You have to login");
    return res.redirect("/login");
  }
  jwt.verify(globaltoken, process.env.JWT_TOKEN, (err, user) => {
    if (err) {
      req.flash("login", "You have to login");
      console.log(err);
      return res.redirect("/login")
    }
    console.log("verified");
    next();
  });
}

app.listen(process.env.PORT);