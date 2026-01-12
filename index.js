const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();
const bcrypt = require("bcrypt");
const cloudinary = require("cloudinary").v2;
const app = express();
const port = process.env.PORT || 5000;
// middlewares
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// MongoDB
const client = new MongoClient(process.env.MONGO_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    const db = client.db("bookwormDB");
    const usersCollection = db.collection("users");
    const booksCollection = db.collection("books");
    const reviewsCollection = db.collection("reviews");

    // middleware
    const auth =
      (roles = []) =>
      (req, res, next) => {
        const token = req.cookies.token;
        if (!token) return res.status(401).send("Unauthorized");

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;

        if (roles.length && !roles.includes(decoded.role)) {
          return res.status(403).send("Forbidden");
        }
        next();
      };

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
    app.post("/api/login", async (req, res) => {
      const user = await usersCollection("users").findOne({
        email: req.body.email,
      });
      if (!user) return res.status(400).send("Invalid credentials");

      const match = await bcrypt.compare(req.body.password, user.password);
      if (!match) return res.status(400).send("Invalid credentials");

      const token = jwt.sign(
        { id: user._id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.cookie("token", token, { httpOnly: true }).send({
        role: user.role,
        name: user.name,
      });
    });

    // Book related API routes
    app.post("/api/books", auth(["admin"]), async (req, res) => {
      await booksCollection.insertOne(req.body);
      res.send({ success: true });
    });
    app.get("/api/books", auth(), async (req, res) => {
      const books = await booksCollection.find().toArray();
      res.send(books);
    });

    // Reviews related API routes
    app.post("/api/reviews", auth(), async (req, res) => {
      await reviewsCollection.insertOne({
        ...req.body,
        userId: req.user.id,
        status: "pending",
        createdAt: new Date(),
      });
      res.send({ success: true });
    });
    app.get("/api/admin/reviews", auth(["admin"]), async (req, res) => {
      const reviews = await reviewsCollection
        .find({ status: "pending" })
        .toArray();
      res.send(reviews);
    });
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);
app.get("/", async (req, res) => {
  res.send("Book Worm Server");
});
// server
app.listen(port, () => {
  console.log("Server running on port", port);
});
