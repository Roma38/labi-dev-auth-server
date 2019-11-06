const express = require("express");
var cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { SECRET_KEY } = require("./config");

const createToken = login => {
  return jwt.sign({ login }, SECRET_KEY);
};

const app = express();
const port = 5000;
const users = []; // использую вместо базы данных

app.use(cors());
app.use(bodyParser.json());

app.post("/register", function(req, res) {
  const { login, password } = req.body;
  const user = users.find(user => user.login === login);

  if (user) {
    return res.status(409).json({ message: "Login already taken!" });
  }

  bcrypt.hash(password, 10, function(err, hash) {
    if (err) {
      return res.status(500).json({ message: "Oops, something went wrong :(" });
    }

    users.push({ login, passwordHash: hash });
    const token = createToken(login);
    res.json({ token });
  });
});

app.post("/login", function(req, res) {
  const { login, password } = req.body;
  const user = users.find(user => user.login === login);

  if (!user) {
    return res.status(400).json({ message: "Invalid login or password" });
  }

  const isValidPassword = bcrypt.compareSync(password, user.passwordHash);

  if (!isValidPassword) {
    return res.status(400).json({ message: "Invalid login or password" });
  }

  const token = createToken(login);
  res.json({ token });
});

app.get("/is-logged-in", function(req, res) {
  const token = req.headers["authorization"];

  if (!token || token === "null") {
    return res.status(401).json({ message: "Unauthenticated" });
  }

  try {
    const { login } = jwt.verify(token, SECRET_KEY);
    res.json({ login });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ message: "Unauthenticated" });
  }
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
