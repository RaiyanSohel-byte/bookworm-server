const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const bcrypt = require("bcrypt");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const jwt = require("jsonwebtoken");

const upload = multer({
  storage: multer.memoryStorage(),
});
const app = express();
const port = process.env.PORT || 5000;
// middlewares
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.urlencoded({ extended: true }));
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
      async (req, res, next) => {
        try {
          const token = req.cookies.token;
          if (!token) return res.status(401).send("Unauthorized");

          const decoded = jwt.verify(token, process.env.JWT_SECRET);

          const user = await usersCollection.findOne(
            { _id: new ObjectId(decoded.id) },
            { projection: { password: 0 } }
          );

          if (!user) return res.status(401).send("User not found");

          req.user = {
            id: user._id.toString(),
            name: user.name,
            email: user.email,
            image: user.photo || null,
            role: user.role,
          };

          if (roles.length && !roles.includes(user.role)) {
            return res.status(403).send("Forbidden");
          }

          next();
        } catch (err) {
          console.error("AUTH ERROR:", err);
          res.status(401).send("Invalid token");
        }
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
      const user = await usersCollection.findOne({
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
    app.get("/api/me", auth(), async (req, res) => {
      const user = await usersCollection.findOne(
        { _id: new ObjectId(req.user.id) },
        { projection: { password: 0 } }
      );

      if (!user) return res.status(404).send("User not found");

      res.send(user);
    });
    app.post("/api/logout", (req, res) => {
      res.clearCookie("token", { httpOnly: true });
      res.send({ success: true });
    });

    // Book related API routes
    app.post(
      "/api/books",
      auth(["admin"]),
      upload.single("cover"),
      async (req, res) => {
        try {
          let coverUrl = "";

          if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = "data:" + req.file.mimetype + ";base64," + b64;

            const uploadResult = await cloudinary.uploader.upload(dataURI, {
              folder: "bookworm-books",
            });

            coverUrl = uploadResult.secure_url;
          }

          const book = {
            title: req.body.title,
            author: req.body.author,
            genre: req.body.genre,
            description: req.body.description,
            cover: coverUrl,
            createdAt: new Date(),
          };

          const result = await booksCollection.insertOne(book);

          res.send({ ...book, _id: result.insertedId });
        } catch (err) {
          console.error("BOOK CREATE ERROR:", err);
          res.status(500).send("Failed to create book");
        }
      }
    );
    app.get("/api/books/:id", auth(), async (req, res) => {
      try {
        const { id } = req.params;
        const book = await booksCollection.findOne({ _id: new ObjectId(id) });

        if (!book) {
          return res.status(404).send("Book not found");
        }

        res.send(book);
      } catch (err) {
        console.error("GET BOOK ERROR:", err);
        res.status(500).send("Failed to load book");
      }
    });
    app.get("/api/books", auth(), async (req, res) => {
      const books = await booksCollection.find().toArray();
      res.send(books);
    });
    app.put(
      "/api/books/:id",
      auth(["admin"]),
      upload.single("cover"),
      async (req, res) => {
        try {
          const { id } = req.params;

          const updateData = {
            title: req.body.title,
            author: req.body.author,
            genre: req.body.genre,
            description: req.body.description,
          };

          if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = `data:${req.file.mimetype};base64,${b64}`;

            const uploadResult = await cloudinary.uploader.upload(dataURI, {
              folder: "bookworm-books",
            });

            updateData.cover = uploadResult.secure_url;
          }

          const result = await booksCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
          );

          if (!result.matchedCount) {
            return res.status(404).send("Book not found");
          }

          const updatedBook = await booksCollection.findOne({
            _id: new ObjectId(id),
          });

          res.send(updatedBook);
        } catch (err) {
          console.error("UPDATE BOOK ERROR:", err);
          res.status(500).send("Failed to update book");
        }
      }
    );

    app.delete("/api/books/:id", auth(["admin"]), async (req, res) => {
      try {
        const { id } = req.params;

        const result = await booksCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).send("Book not found");
        }

        res.send({ success: true });
      } catch (err) {
        console.error("DELETE BOOK ERROR:", err);
        res.status(500).send("Failed to delete book");
      }
    });

    // Reviews related API routes
    app.post("/api/reviews", auth(), async (req, res) => {
      const { bookId, comment, rating } = req.body;
      if (!bookId || !comment || !rating)
        return res.status(400).send("Incomplete review");

      try {
        const user = await usersCollection.findOne(
          { _id: new ObjectId(req.user.id) },
          { projection: { password: 0 } }
        );

        await reviewsCollection.insertOne({
          bookId: new ObjectId(bookId),
          comment,
          rating,
          userId: user._id,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            image: user.photo || null,
          },
          status: "pending",
          createdAt: new Date(),
        });

        res.send({ success: true });
      } catch (err) {
        console.error("POST REVIEW ERROR:", err);
        res.status(500).send("Failed to post review");
      }
    });

    app.get("/api/admin/reviews", auth(["admin"]), async (req, res) => {
      try {
        const reviews = await reviewsCollection
          .aggregate([
            { $match: { status: "pending" } },
            {
              $lookup: {
                from: "users",
                localField: "userId",
                foreignField: "_id",
                as: "user",
              },
            },
            {
              $lookup: {
                from: "books",
                localField: "bookId",
                foreignField: "_id",
                as: "book",
              },
            },
            {
              $project: {
                rating: 1,
                comment: 1,
                status: 1,
                createdAt: 1,
                user: { $arrayElemAt: ["$user", 0] },
                book: { $arrayElemAt: ["$book", 0] },
              },
            },
          ])
          .toArray();

        res.send(reviews);
      } catch (err) {
        console.error("ADMIN REVIEWS ERROR:", err);
        res.status(500).send("Failed to fetch reviews");
      }
    });

    app.patch("/api/admin/reviews/:id", auth(["admin"]), async (req, res) => {
      const { status } = req.body;

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).send("Invalid status");
      }

      await reviewsCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status } }
      );

      res.send({ success: true });
    });
    app.delete("/api/admin/reviews/:id", auth(["admin"]), async (req, res) => {
      await reviewsCollection.deleteOne({
        _id: new ObjectId(req.params.id),
      });

      res.send({ success: true });
    });

    app.get("/api/reviews", auth(), async (req, res) => {
      const { bookId } = req.query;
      if (!bookId) return res.status(400).send("Book ID missing");

      try {
        const bookReviews = await reviewsCollection
          .aggregate([
            { $match: { bookId: new ObjectId(bookId), status: "approved" } },
            {
              $lookup: {
                from: "users",
                localField: "userId",
                foreignField: "_id",
                as: "user",
              },
            },
            { $unwind: "$user" },
            {
              $project: {
                _id: 1,
                bookId: 1,
                rating: 1,
                comment: 1,
                status: 1,
                createdAt: 1,
                user: {
                  id: "$user._id",
                  name: "$user.name",
                  email: "$user.email",
                  image: "$user.photo",
                },
              },
            },
          ])
          .sort({ createdAt: -1 })
          .toArray();

        res.send(bookReviews);
      } catch (err) {
        console.error("Failed to fetch reviews:", err);
        res.status(500).send("Failed to fetch reviews");
      }
    });

    // admin stats API route
    app.get("/api/admin/stats", auth(["admin"]), async (req, res) => {
      try {
        // Count total users
        const usersCount = await usersCollection.countDocuments();

        // Count total books
        const booksCount = await booksCollection.countDocuments();

        // Count pending reviews
        const pendingReviewsCount = await reviewsCollection.countDocuments({
          status: "pending",
        });

        // Aggregate books by genre
        const genresAgg = await booksCollection
          .aggregate([
            { $group: { _id: "$genre", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
          ])
          .toArray();

        const genres = genresAgg.map((g) => ({
          genre: g._id,
          count: g.count,
        }));

        res.send({
          users: usersCount,
          books: booksCount,
          pendingReviews: pendingReviewsCount,
          genres,
        });
      } catch (err) {
        console.error("STATS ERROR:", err);
        res.status(500).send("Failed to fetch stats");
      }
    });
    // user stats API route
    app.get("/api/user/stats", auth(), async (req, res) => {
      try {
        const userId = req.user.id;

        const booksRead = await reviewsCollection.countDocuments({
          userId,
          status: "approved",
        });

        const totalBooks = await booksCollection.countDocuments();
        const goal = 50;

        const monthly = await reviewsCollection
          .aggregate([
            { $match: { userId, status: "approved" } },
            {
              $group: {
                _id: { $month: "$createdAt" },
                count: { $sum: 1 },
              },
            },
            { $sort: { _id: 1 } },
          ])
          .toArray();

        const genresAgg = await reviewsCollection
          .aggregate([
            { $match: { userId, status: "approved" } },
            {
              $lookup: {
                from: "books",
                localField: "bookId",
                foreignField: "_id",
                as: "book",
              },
            },
            { $unwind: "$book" },
            {
              $group: {
                _id: "$book.genre",
                count: { $sum: 1 },
              },
            },
          ])
          .toArray();

        const genres = genresAgg.map((g) => ({
          genre: g._id,
          count: g.count,
        }));

        res.send({
          booksRead,
          totalBooks,
          goal,
          monthly,
          genres,
        });
      } catch (err) {
        console.error("USER STATS ERROR:", err);
        res.status(500).send("Failed to load user stats");
      }
    });

    // recommendations API route
    app.get("/api/recommendations", auth(), async (req, res) => {
      try {
        const books = await booksCollection.find().limit(10).toArray();

        res.send(books);
      } catch (err) {
        console.error("RECOMMENDATION ERROR:", err);
        res.status(500).send("Failed to fetch recommendations");
      }
    });
    // library API route
    app.get("/api/library", auth(), async (req, res) => {
      try {
        const user = await usersCollection.findOne(
          { _id: new ObjectId(req.user.id) },
          { projection: { shelves: 1 } }
        );

        if (!user) {
          return res.status(404).send("User not found");
        }

        res.send(user.shelves);
      } catch (err) {
        console.error("LIBRARY ERROR:", err);
        res.status(500).send("Failed to load library");
      }
    });
    app.post("/api/users/shelves", auth(), async (req, res) => {
      try {
        const { bookId, shelf, progress, bookInfo } = req.body;
        if (!bookId || !shelf)
          return res.status(400).send("Book ID and shelf required");

        const validShelves = ["want", "reading", "read"];
        if (!validShelves.includes(shelf))
          return res.status(400).send("Invalid shelf type");

        let entry;
        if (shelf === "reading") {
          entry = {
            bookId: new ObjectId(bookId),
            title: bookInfo?.title,
            cover: bookInfo?.cover,
            pagesRead: progress?.pagesRead || 0,
            totalPages: progress?.totalPages || 0,
          };
        } else {
          entry = {
            bookId: new ObjectId(bookId),
            title: bookInfo?.title,
            cover: bookInfo?.cover,
          };
        }

        await usersCollection.updateOne(
          { _id: new ObjectId(req.user.id) },
          { $addToSet: { [`shelves.${shelf}`]: entry } }
        );

        res.send({ success: true });
      } catch (err) {
        console.error("ADD TO SHELF ERROR:", err);
        res.status(500).send("Failed to add book to shelf");
      }
    });

    // Image upload
    app.post("/api/upload", upload.single("image"), async (req, res) => {
      try {
        if (!req.file) {
          return res.status(400).send("No file uploaded");
        }

        const b64 = Buffer.from(req.file.buffer).toString("base64");
        const dataURI = "data:" + req.file.mimetype + ";base64," + b64;

        // Upload to Cloudinary
        const result = await cloudinary.uploader.upload(dataURI, {
          folder: "bookworm-users",
        });

        res.send({ url: result.secure_url });
      } catch (err) {
        console.error("UPLOAD ERROR:", err);
        res.status(500).send("Image upload failed");
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // await client.close();
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
