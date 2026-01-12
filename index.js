const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
