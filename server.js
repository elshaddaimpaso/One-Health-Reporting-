"use strict";
// Local development only. On Vercel, api/index.js is the function and public/ is served by the CDN.
const path = require("path");
const express = require("express");
const api = require("./api/index.js");

const PORT = process.env.PORT || 3000;
const local = express();
local.use(express.static(path.join(__dirname, "public")));
local.use(api);
local.listen(PORT, () => console.log(`One Health running on http://localhost:${PORT}`));
