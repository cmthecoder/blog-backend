require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { default: mongoose } = require("mongoose");
const User = require("./models/User");
const Post = require("./models/Post");
const bcrypt = require("bcrypt");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const uploadMiddleware = multer({ dest: "uploads/" });
const fs = require("fs");

const salt = bcrypt.genSaltSync(10);
const secret = `${process.env.SECRET}`;

app.use(cors({ credentials: true, origin: `${process.env.HOST}` }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(__dirname + '/uploads'))

mongoose.connect(`${process.env.DATABASE_URL}`);

// Create a new User
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (err) {
    res.status(400).json(err);
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Grab the user
  const userDoc = await User.findOne({ username });

  const passOk = bcrypt.compareSync(password, userDoc.password);

  if (passOk) {
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res.cookie("token", token).json({
        id: userDoc._id,
        username,
      });
    });
  } else {
    res.status(400).json("Wrong credientials!");
  }
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies;

  try {
    const userInfo = jwt.verify(token, secret);
    res.json(userInfo);
  } catch (error) {
    console.error("Error verifying JWT token:", error);
    res.status(401).json({ message: "Unauthorized" });
  }
});

app.post("/logout", (req, res) => {
  res.cookie("token", "").json("ok");
});

// The following code provides the ability to upload files
app.post("/post", uploadMiddleware.single("file"), async (req, res) => {
  const { originalname, path } = req.file;
  const parts = originalname.split(".");
  const ext = parts[parts.length - 1];
  const newPath = path + "." + ext;
  fs.renameSync(path, newPath);

  const { token } = req.cookies;
  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) throw err;
    const { title, summary, content } = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath,
      author: info.id,
    });

    res.json(postDoc);
  });
});

app.get("/post", async (req, res) => {
  // We can define what we want to select
  res.json(
    await Post.find()
      .populate("author", ["username"])
      .sort({ createAt: -1 })
      .limit(20)
  );
});

app.listen(`${process.env.PORT}`);
