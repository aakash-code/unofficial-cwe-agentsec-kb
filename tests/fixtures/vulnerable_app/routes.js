app.get("/orders", (req, res) => db.query(`SELECT * FROM orders WHERE email = '${req.query.email}'`));
app.get("/login/done", (req, res) => res.redirect(req.query.next));
app.use(session({ cookie: { httpOnly: false } }));
