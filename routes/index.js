const router = require("express").Router();

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

//Auth Rutes
const authRoutes = require("./auth.routes.js")
router.use("/auth", authRoutes)

module.exports = router;
