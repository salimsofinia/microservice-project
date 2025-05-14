// const bcrypt = require("bcrypt");

// const hashPassword = async (password) => {
//   const salt = await bcrypt.genSalt(12);
//   const hash = await bcrypt.hash(password, salt);
//   console.log(salt);
//   console.log(hash);
// };

// hashPassword("monkey");

require("dotenv").config();

// imports =====================================================================
const express = require("express");
const User = require("./models/user");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const path = require("path");
const session = require("express-session");

// mongodb connection ==========================================================
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✔️  MongoDB Atlas connected"))
  .catch((err) => {
    console.error("❌  MongoDB connection error:", err);
  });

// app. ========================================================================
const app = express();

app.set("view engine", "ejs");
app.set("views", "views");

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET }));

// authentication middleware

const requireLogin = (req, res, next) => {
  if (!req.session.user_id) {
    return res.redirect("/login");
  }
  next();
};

// routes ======================================================================

// /register ===================================================================

app.get("/register", (req, res) => {
  req.session.destroy();
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { password, username } = req.body;
  const salt = await bcrypt.genSalt(12);
  const hash = await bcrypt.hash(password, salt);
  const user = new User({
    username,
    password: hash,
  });
  await user.save();
  res.redirect("/login");
});

// /login ======================================================================

app.get("/login", (req, res) => {
  req.session.destroy();
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  const validPassword = await bcrypt.compare(password, user.password);
  if (validPassword) {
    req.session.user_id = user._id;
    res.redirect("/home");
  } else {
    res.redirect("/login");
  }
});

// /home =======================================================================

app.get("/home", requireLogin, (req, res) => {
  res.render("home");
});

// /moderator ==================================================================

app.get("/moderator", requireLogin, (req, res) => {
  res.render("moderator");
});

// localhost:3000 ==============================================================

app.listen(3000, () => {
  console.log("SERVER IS SERVING!");
});
