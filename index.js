import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
    })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets.ejs");
    } else {
        res.redirect("/login");
    }
});

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "/secrets",
        failureRedirect: "/login",
    })
);

app.post("/register", async (req, res, next) => {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password: ", err);
                    return next(err);
                }

                await db.query(
                    "INSERT INTO users (email, password) VALUES ($1, $2)",
                    [email, hash]
                );

                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                });
            });
        }
    } catch (err) {
        console.log(err);
        next(err);
    }
});

passport.use(
    new Strategy(async function verify(username, password, cb) {
        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);

            if (result.rows.length > 0) {
                const user = result.rows[0];
                const storedHashedPassword = user.password;

                bcrypt.compare(password, storedHashedPassword, (err, isValid) => {
                    if (err) {
                        console.error("Error comparing passwords:", err);
                        return cb(err);
                    }
                    if (isValid) {
                        return cb(null, user);
                    } else {
                        return cb(null, false);
                    }
                });
            } else {
                return cb(null, false);
            }
        } catch (err) {
            console.log(err);
            return cb(err);
        }
    })
);

passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        if (result.rows.length > 0) {
            cb(null, result.rows[0]);
        } else {
            cb(null, false);
        }
    } catch (err) {
        cb(err);
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
