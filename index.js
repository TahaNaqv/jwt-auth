const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
let refreshTokens = [];

app.use(express.json());

const auth = (req, res, next) => {
  let token = req.headers["authorization"];
  token = token.split(" ")[1];

  if (!token) {
    return res.status(404).json({ message: "token not found! " });
  }
  jwt.verify(token, "access", (err, user) => {
    if (!err) {
      req.user = user;
      next();
    } else {
      return res.status(403).json({ message: "user not authenticated! " });
    }
  });
};

app.post("/renewaccesstoken", (req, res) => {
  const refreshToken = req.body.token;
  if (!refreshToken || !refreshTokens.includes(refreshToken)) {
    res.status(403).json({ message: "user not authenticated! " });
  }
  jwt.verify(refreshToken, "refresh", (err, user) => {
    if (!err) {
      const accessToken = jwt.sign({ username: user.name }, "access", {
        expiresIn: "20s",
      });
      return res.status(200).json({ accessToken });
    } else {
      return res.status(403).json({ message: "user not authenticated! " });
    }
  });
});

app.post("/protected", auth, (req, res) => {
  res.send("inside protected route");
});

app.post("/login", (req, res) => {
  const user = req.body.user;
  if (!user) {
    return res.status(404).json({ message: "empty body! " });
  }
  let accesstoken = jwt.sign(user, "access", { expiresIn: "20s" });
  let refreshtoken = jwt.sign(user, "refresh", { expiresIn: "7d" });
  refreshTokens.push(refreshtoken);
  return res.status(200).json({ accesstoken, refreshtoken });
});

app.listen(3000);
