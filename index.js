const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient } = require("mongodb");
require("dotenv").config();
const bcrypt = require("bcrypt");

const app = express();
const port = process.env.PORT || 5000;
// middlewares
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// MongoDB
const client = new MongoClient(process.env.MONGO_URI);
await client.connect();
const db = client.db("bookwormDB");
const usersCollection = db.collection("users");

//auth API routes
app.post("/api/register", async (req, res) => {
  const { name, email, password, photo } = req.body;
  const existing = await usersCollection.findOne({ email });
  if (existing) return res.status(400).send("Email exists");

  const hashed = await bcrypt.hash(password, 10);
  await usersCollection.insertOne({
    name,
    email,
    password: hashed,
    photo,
    role: "user",
    shelves: { want: [], reading: [], read: [] },
    createdAt: new Date(),
  });

  res.send({ success: true });
});

// server
app.listen(port, () => {
  console.log("Server running on port", port);
});
