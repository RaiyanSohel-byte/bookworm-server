const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 5000;
// middlewares
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// server
app.listen(port, () => {
  console.log("Server running on port", port);
});
