const router = require("express").Router();

const User = require("../models/User.model.js");

const bcrypt = require("bcryptjs");


//ITERACIÓN 1
router.get("/signup", (req, res, next) =>{
    res.render("auth/signup.hbs")
})

router.post("/signup", async (req, res, next) =>{
    const {username, password} = req.body
    //CLAÚSULAS DE GUARDIA
    //Revisamos que no estén los campos vacíos
    if(username === "" || password === ""){
        res.render("auth/signup.hbs", { errorMessage : "Todos los campos deben estar rellenados."})
        return
    }
    //Comprobamos que la contraseña sea segura
    let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/
    if(passwordRegex.test(password) === false){
        res.render("auth/signup.hbs", { errorMessage : "La contraseña debe tener 1 mayúscula, 1 minúscula, 1 número y mínimo 8 carácteres."})
        return
    }
    
    try {
        //Comprobamos que el nombre del usuario no este creado en la BD
        const foundUsername = await User.findOne({username})
        if(foundUsername !== null){
            res.render("auth/signup.hbs", {errorMessage: "El nombre de usuario ya esta en uso."})
            return
        }
        //Ciframos la contraseña 
        const salt = await bcrypt.genSalt(10)
        const hashesPassword = await bcrypt.hash(password, salt)
        await User.create({
            username,
            password:hashesPassword
        }) 
        res.redirect("/auth/login")
    } catch (err) {
        next(err)
    }


})

router.get("/login", (req, res, next) =>{
    res.render("auth/login.hbs")
})


module.exports = router;
