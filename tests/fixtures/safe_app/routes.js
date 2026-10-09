app.get("/orders", (req, res) => db.query("SELECT * FROM orders WHERE email = $1", [req.query.email]));
app.get("/login/done", (req, res) => res.redirect("/home"));
app.use(session({ cookie: { httpOnly: true, secure: true, sameSite: "lax" } }));
