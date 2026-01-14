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
    const genresCollection = db.collection("genres");

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
    // Get all users
    app.get("/api/admin/users", auth(["admin"]), async (req, res) => {
      try {
        const users = await usersCollection
          .find({}, { projection: { password: 0 } })
          .toArray();
        res.send(users);
      } catch (err) {
        console.error("FETCH USERS ERROR:", err);
        res.status(500).send("Failed to fetch users");
      }
    });
    app.put("/api/admin/promote", auth(["admin"]), async (req, res) => {
      const { email } = req.body;
      const result = await usersCollection.updateOne(
        { email },
        { $set: { role: "admin" } }
      );
      if (result.matchedCount === 0)
        return res.status(404).send("User not found");
      res.send({ success: true });
    });

    app.put("/api/admin/demote", auth(["admin"]), async (req, res) => {
      const { email } = req.body;

      if (!email) return res.status(400).send("Email is required");

      try {
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send("User not found");

        if (user._id.toString() === req.user.id) {
          return res.status(400).send("You cannot demote yourself");
        }

        if (user.role !== "admin") {
          return res.status(400).send("User is not an admin");
        }

        await usersCollection.updateOne({ email }, { $set: { role: "user" } });

        res.send({ success: true, message: `${email} demoted to user` });
      } catch (err) {
        console.error("DEMOTE USER ERROR:", err);
        res.status(500).send("Failed to demote user");
      }
    });

    app.delete("/api/admin/users/:id", auth(["admin"]), async (req, res) => {
      const { id } = req.params;
      const result = await usersCollection.deleteOne({ _id: new ObjectId(id) });
      if (result.deletedCount === 0)
        return res.status(404).send("User not found");
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
            totalPages: parseInt(req.body.totalPages, 10) || 0,
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
    // GET /api/books
    app.get("/api/books", auth(), async (req, res) => {
      try {
        const { search, genre, page = 1, limit = 20 } = req.query;

        const filter = {};
        if (search) {
          filter.$or = [
            { title: { $regex: search, $options: "i" } },
            { author: { $regex: search, $options: "i" } },
          ];
        }
        if (genre) {
          filter.genre = genre;
        }

        const pageNum = parseInt(page, 10);
        const limitNum = parseInt(limit, 10);
        const skip = (pageNum - 1) * limitNum;

        const total = await booksCollection.countDocuments(filter);
        const books = await booksCollection
          .find(filter)
          .skip(skip)
          .limit(limitNum)
          .toArray();

        res.send({
          books,
          total,
          page: pageNum,
          pages: Math.ceil(total / limitNum),
        });
      } catch (err) {
        console.error("FETCH BOOKS ERROR:", err);
        res.status(500).send("Failed to fetch books");
      }
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
            totalPages: parseInt(req.body.totalPages, 10) || 0,
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

    // Genre related API routes
    app.get("/api/admin/genres", auth(), async (req, res) => {
      const genres = await genresCollection.find().toArray();
      res.send(genres);
    });

    app.post("/api/admin/genres", auth(["admin"]), async (req, res) => {
      const { name } = req.body;
      if (!name) return res.status(400).send("Name is required");

      const existing = await genresCollection.findOne({ name });
      if (existing) return res.status(400).send("Genre already exists");

      const result = await genresCollection.insertOne({ name });
      res.send({ _id: result.insertedId, name });
    });

    app.put("/api/admin/genres/:id", auth(["admin"]), async (req, res) => {
      try {
        const { id } = req.params;
        const { name } = req.body;

        if (!name) return res.status(400).send("Name is required");

        if (!ObjectId.isValid(id)) {
          return res.status(400).send("Invalid Genre ID format");
        }

        const updatedGenre = await genresCollection.findOneAndUpdate(
          { _id: new ObjectId(id) },
          { $set: { name } },
          { returnDocument: "after" }
        );

        if (!updatedGenre) {
          return res.status(404).send("Genre not found");
        }

        res.send(updatedGenre);
      } catch (err) {
        console.error("UPDATE GENRE ERROR:", err);
        res.status(500).send("Internal Server Error: Failed to update genre");
      }
    });

    app.delete("/api/admin/genres/:id", auth(["admin"]), async (req, res) => {
      const { id } = req.params;
      const result = await genresCollection.deleteOne({
        _id: new ObjectId(id),
      });

      if (result.deletedCount === 0)
        return res.status(404).send("Genre not found");
      res.send({ success: true });
    });

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
        const userObjectId = new ObjectId(req.user.id);

        const booksRead = await reviewsCollection.countDocuments({
          userId: userObjectId,
          status: "approved",
        });

        const totalBooks = await booksCollection.countDocuments();
        const goal = 50;

        const monthly = await reviewsCollection
          .aggregate([
            { $match: { userId: userObjectId, status: "approved" } },
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
            { $match: { userId: userObjectId, status: "approved" } },
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
        const user = await usersCollection.findOne(
          { _id: new ObjectId(req.user.id) },
          { projection: { shelves: 1 } }
        );

        const readBooks = user.shelves?.read || [];
        let recommendedBooks = [];

        if (readBooks.length >= 3) {
          // Top genre recommendation logic
          const genreCounts = {};
          readBooks.forEach((b) => {
            if (!b.genre) return;
            genreCounts[b.genre] = (genreCounts[b.genre] || 0) + 1;
          });

          const topGenres = Object.entries(genreCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3)
            .map(([g]) => g);

          recommendedBooks = await booksCollection
            .find({
              genre: { $in: topGenres },
              _id: { $nin: readBooks.map((b) => b.bookId) },
            })
            .sort({ avgRating: -1, shelvesCount: -1 })
            .limit(15)
            .toArray();

          recommendedBooks = recommendedBooks.map((b) => ({
            ...b,
            reason: `Matches your preference for ${b.genre} and highly rated by the community.`,
          }));
        }

        // Fallback: if not enough read books or no matches
        if (recommendedBooks.length === 0) {
          const popularBooks = await booksCollection
            .find()
            .sort({ avgRating: -1, shelvesCount: -1 })
            .limit(12)
            .toArray();

          // Always use `$sample` safely even if collection is small
          const randomBooks = await booksCollection
            .aggregate([
              {
                $sample: {
                  size: Math.min(3, await booksCollection.countDocuments()),
                },
              },
            ])
            .toArray();

          recommendedBooks = [...popularBooks, ...randomBooks].map((b) => ({
            ...b,
            reason: "Popular choice among readers.",
          }));
        }

        res.send(recommendedBooks);
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
    // Update book progress in shelves
    app.patch("/api/users/shelves/:bookId", auth(), async (req, res) => {
      try {
        const { bookId } = req.params;
        const { pagesRead, shelf } = req.body;

        if (!bookId || pagesRead == null || !shelf)
          return res.status(400).send("Missing required data");

        const validShelves = ["want", "reading", "read"];
        if (!validShelves.includes(shelf))
          return res.status(400).send("Invalid shelf");

        // Remove from all shelves first (in case user changes shelf)
        const updateOps = {
          $pull: {
            "shelves.want": { bookId: new ObjectId(bookId) },
            "shelves.reading": { bookId: new ObjectId(bookId) },
            "shelves.read": { bookId: new ObjectId(bookId) },
          },
        };

        await usersCollection.updateOne(
          { _id: new ObjectId(req.user.id) },
          updateOps
        );

        // Add back to the correct shelf with updated progress
        let entry = { bookId: new ObjectId(bookId) };
        if (shelf === "reading") {
          entry.pagesRead = pagesRead;
          const book = await booksCollection.findOne({
            _id: new ObjectId(bookId),
          });
          entry.totalPages = book?.totalPages || 0; // use total pages from book
          entry.title = book?.title;
          entry.cover = book?.cover;
        }

        await usersCollection.updateOne(
          { _id: new ObjectId(req.user.id) },
          { $addToSet: { [`shelves.${shelf}`]: entry } }
        );

        res.send({ success: true });
      } catch (err) {
        console.error("UPDATE SHELF ERROR:", err);
        res.status(500).send("Failed to update shelf");
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
