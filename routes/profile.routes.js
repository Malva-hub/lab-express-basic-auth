const router = require("express").Router();

const isLoggedIn = require("../middlewares/auth.js")

router.get("/main", isLoggedIn, (req, res, next) =>{
    res.render("profile/main.hbs")
})

router.get("/private", isLoggedIn, (req, res, next) =>{
    res.render("profile/private.hbs")
} )

module.exports = router;