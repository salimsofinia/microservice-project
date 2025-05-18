// imports =====================================================================
require("dotenv").config();

const express = require("express");
const User = require("./models/user");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const path = require("path");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");

const { check, validationResult } = require("express-validator");

// .env ========================================================================

const COOKIE_SECRET = process.env.COOKIE_SECRET; // for cookie-parser
const SESSION_SECRET = process.env.SESSION_SECRET; // for express-session
const JWT_SECRET = process.env.JWT_SECRET; // for signing your JWT payload

// Session (signed with SESSION_SECRET)
// Signed cookie (holding the JWT, signed with COOKIE_SECRET)
// JWT payload (signed/verified with JWT_SECRET)

// mongodb connection ==========================================================
console.log("⚡️ Connecting to MongoDB at:", process.env.MONGODB_URI);
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
app.set("trust proxy", 1);

app.set("view engine", "ejs");
app.set("views", "views");

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));

app.use(express.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // maxAge: 1000 * 60 * 60    // 1 hour
      maxAge: 1000 * 30, // 30sec
      // express-session automatically signs this cookie with SESSION_SECRET
    },
  })
);

// allow max 5 attempts per 1 hour on login
const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: "Too many login attempts, please try again later.",
});
app.use("/login", loginLimiter);

// allow max 5 registrations per hour per IP
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message:
    "Too many accounts created from this IP, please try again after an hour.",
});
app.use("/register", registerLimiter);

// deny user ===================================================================

const denyUser = async (identifier) => {
  try {
    // pick filter based on whether it looks like an ObjectId
    const filter = mongoose.Types.ObjectId.isValid(identifier)
      ? { _id: identifier }
      : { username: identifier };

    const updated = await User.findOneAndUpdate(
      filter,
      { $set: { denylist: "deny" } },
      { new: true }
    );

    if (!updated) {
      console.error(`❌ No user found for identifier="${identifier}"`);
    } else {
      console.log(`✅ User "${updated.username}" is now denied.`);
    }
  } catch (err) {
    console.error("Error updating denylist:", err);
  }
};

// denylist middleware =========================================================

async function checkDenyStatus(req, res, next) {
  try {
    let userDoc;

    // If they've already authenticated (e.g. /home), look up by ID
    if (req.user?.id) {
      userDoc = await User.findById(req.user.id);
    }
    // If they're registering (no req.user yet), look up by the submitted username
    else if (req.body?.username) {
      userDoc = await User.findOne({ username: req.body.username });
    }

    // No user or no denylist field → “not found”
    if (!userDoc || typeof userDoc.denylist === "undefined") {
      return res.send("No denylist value found");
    }

    // Allow through
    if (userDoc.denylist === "allow") {
      return next();
    }

    // Explicit deny → force login
    if (userDoc.denylist === "deny") {
      return res.redirect("/login");
    }

    // Any other value
    return res.send("Unknown denylist value");
  } catch (err) {
    console.error("Denylist check failed:", err);
    return res.status(500).send("Server error");
  }
}

// authentication middleware ===================================================

const requireAuth = async (req, res, next) => {
  // 1️⃣ Try to verify the JWT (so we always have an id/username to blacklist)
  const token = req.signedCookies?.token;
  let payload;
  try {
    if (!token) throw new Error("No token");
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    // Token missing/invalid → blacklist by session if still there
    const fallbackUsername = req.session?.user?.username;
    if (fallbackUsername) {
      await denyUser(fallbackUsername);
    }
    req.session?.destroy(() => {});
    res.clearCookie("connect.sid");
    res.clearCookie("token");
    return res.redirect("/login");
  }

  // 2️⃣ Now that the token is valid, check the session
  const sessionUser = req.session?.user;
  if (!sessionUser || payload.id !== sessionUser.id) {
    // Session missing or mismatched → blacklist via payload info
    const toDeny = payload.username || payload.id;
    await denyUser(toDeny);
    req.session.destroy(() => {});
    res.clearCookie("connect.sid");
    res.clearCookie("token");
    return res.redirect("/login");
  }

  // 3️⃣ All good → attach user and continue
  req.user = payload;
  next();
};

const requireMod = async (req, res, next) => {
  if (req.user.role !== "mod") {
    // blacklist them
    await denyUser(req.session.user.username);
    // destroy their session + cookies
    req.session.destroy(() => {});
    res.clearCookie("connect.sid");
    res.clearCookie("token");
    // kick them back to login
    return res.redirect("/login");
  }
  next();
};

// routes ======================================================================

// /register ===================================================================

app.get("/register", (req, res) => {
  req.session.destroy();
  res.clearCookie("connect.sid");
  res.clearCookie("token");
  res.render("register", { errors: [] });
});

app.post(
  "/register",
  [
    check("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isAlphanumeric()
      .withMessage("Username must be alphanumeric"),
    check("password")
      .isLength({ min: 20 })
      .withMessage("Password must be at least 20 characters"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render("register", { errors: errors.array() });
    }
    const { password, username } = req.body;
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);
    const user = new User({
      username,
      password: hash,
    });
    await user.save();
    req.session.destroy(() => {});
    res.clearCookie("connect.sid");
    res.clearCookie("token");
    res.redirect("/login");
  }
);

// /login ======================================================================

app.get("/login", (req, res) => {
  req.session.destroy();
  res.clearCookie("connect.sid");
  res.clearCookie("token");
  res.render("login", { errors: [] });
});

app.post(
  "/login",
  [
    check("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isAlphanumeric()
      .withMessage("Username must be alphanumeric"),
    check("password")
      .isLength({ min: 20 })
      .withMessage("Password must be at least 20 characters"),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // re-render login page with errors
      return res.status(400).render("login", { errors: errors.array() });
    }
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      // no such user → show generic “invalid credentials” message
      return res
        .status(401)
        .render("login", { errors: [{ msg: "Invalid username or password" }] });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      // wrong password → same generic message
      return res
        .status(401)
        .render("login", { errors: [{ msg: "Invalid username or password" }] });
    }

    // — if we reach here, username & password are good —
    // build session
    req.session.user = {
      id: user._id.toString(),
      username: user.username,
      role: user.role,
      denylist: user.denylist,
    };

    // build JWT
    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        role: user.role,
        denylist: user.denylist,
      },
      JWT_SECRET,
      { expiresIn: "30sec" }
    );

    // store token in both session and cookie
    res.cookie("token", token, {
      httpOnly: true,
      signed: true,
      sameSite: "lax",
      // maxAge: 1000 * 60 * 60    // 1 hour
      maxAge: 1000 * 30, // 30sec
    });

    // role-based redirect
    if (user.role === "mod") {
      return res.redirect("/moderator");
    }
    return res.redirect("/home");
  }
);

// /home =======================================================================

// app.get("/home", requireAuth, (req, res) => {
//   res.render("home");
// });

app.get("/home", requireAuth, checkDenyStatus, (req, res) => {
  // send them to /home/<their-username>
  return res.redirect(`/home/${req.session.user.username}`);
});

app.get(
  "/home/:username",
  requireAuth,
  checkDenyStatus,
  async (req, res, next) => {
    try {
      const { username } = req.params;

      // optional: prevent someone else viewing another user's page
      if (username !== req.session.user.username) {
        return res.status(403).send("Forbidden");
      }

      // you could also re-fetch from the DB if you want fresh data:
      // const user = await User.findOne({ username });
      // if (!user) return res.status(404).render("404");

      res.render("home", { user: req.session.user });
    } catch (err) {
      next(err);
    }
  }
);

// /moderator ==================================================================

app.get(
  "/moderator",
  requireAuth,
  checkDenyStatus,
  requireMod,
  async (req, res) => {
    // extra guard: only “mod” can see this page
    if (req.user.role !== "mod") {
      await denyUser(req.session.user.username);
      req.session.destroy(() => {});
      res.clearCookie("connect.sid");
      res.clearCookie("token");
      return res.redirect("/login");
    }
    return res.redirect(`/moderator/${req.session.user.username}`);
  }
);

app.get(
  "/moderator/:username",
  requireAuth,
  checkDenyStatus,
  requireMod,
  async (req, res, next) => {
    try {
      const { username } = req.params;

      // optional: prevent someone else viewing another user's page
      if (username !== req.session.user.username) {
        return res.status(403).send("Forbidden");
      }

      // you could also re-fetch from the DB if you want fresh data:
      // const user = await User.findOne({ username });
      // if (!user) return res.status(404).render("404");

      res.render("moderator", { user: req.session.user });
    } catch (err) {
      next(err);
    }
  }
);

// localhost:3000 ==============================================================

app.listen(process.env.PORT, () => {
  console.log(`SERVER IS SERVING ON ${process.env.PORT}!`);
});
