const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient } = require("mongodb");
require("dotenv").config();

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

// server
app.listen(port, () => {
  console.log("Server running on port", port);
});
