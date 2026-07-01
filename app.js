const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./db");

const app = express();
const PORT = 3000;

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: "login-system-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// 登录检查
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

// 管理员权限检查
function requireAdmin(req, res, next) {
  if (req.session.user.role !== "admin") {
    return res.status(403).send("Access denied. Admin only.");
  }
  next();
}

// 首页
app.get("/", (req, res) => {
  res.redirect("/login");
});

// 登录页面
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

// 登录处理
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        return res.render("login", { error: "Database error." });
      }

      if (!user) {
        return res.render("login", { error: "Invalid username or password." });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.render("login", { error: "Invalid username or password." });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
      };

      if (user.role === "admin") {
        res.redirect("/admin");
      } else {
        res.redirect("/user");
      }
    }
  );
});

// 管理员页面
app.get("/admin", requireLogin, requireAdmin, (req, res) => {
  db.all("SELECT id, username, role FROM users", [], (err, users) => {
    if (err) {
      return res.send("Database error.");
    }

    res.render("admin", {
      user: req.session.user,
      users: users,
    });
  });
});

// 普通用户页面
app.get("/user", requireLogin, (req, res) => {
  res.render("user", {
    user: req.session.user,
  });
});

// 登出
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});