const router = require("express").Router();

const User = require("../models/User.model.js");

const bcrypt = require("bcryptjs");

//ITERACIÓN 1
router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

router.post("/signup", async (req, res, next) => {
  const { username, password } = req.body;
  //CLAÚSULAS DE GUARDIA
  //Revisamos que no estén los campos vacíos
  if (username === "" || password === "") {
    res.render("auth/signup.hbs", {
      errorMessage: "Todos los campos deben estar rellenados.",
    });
    return;
  }
  //Comprobamos que la contraseña sea segura
  let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/;
  if (passwordRegex.test(password) === false) {
    res.render("auth/signup.hbs", {
      errorMessage:
        "La contraseña debe tener 1 mayúscula, 1 minúscula, 1 número y mínimo 8 carácteres.",
    });
    return;
  }

  try {
    //Comprobamos que el nombre del usuario no este creado en la BD
    const foundUsername = await User.findOne({ username });
    if (foundUsername !== null) {
      res.render("auth/signup.hbs", {
        errorMessage: "El nombre de usuario ya esta en uso.",
      });
      return;
    }
    //Ciframos la contraseña
    const salt = await bcrypt.genSalt(10);
    const hashesPassword = await bcrypt.hash(password, salt);
    await User.create({
      username,
      password: hashesPassword,
    });
    res.redirect("/auth/login");
  } catch (err) {
    next(err);
  }
});

// ITERACIÓN 2

// GET => "/auth/login" => Renderiza el formulario de inicio de sesión
router.get("/login", (req, res, next) => {
  res.render("auth/login.hbs");
});

// POST => Verificar credenciales del Usuario y permitir acceso
router.post("/login", async (req, res, next) => {
  const { username, password } = req.body;

  // Comprobar que los campos no estén vacios
  if (username === "" || password === "") {
    res.render("auth/login.hbs", {
      errorMessage: "Todos los campos deben estar rellenos",
    });
    return;
  }

  try {
    //Buscamos que el nombre de usuario este en nuestra BD
    const foundUsername = await User.findOne({ username });
    if (foundUsername === null) {
      res.render("auth/login.hbs", { errorMessage: "Usuario no registrado " });
      return;
    }

    //Comprobar contraseña
    const isPasswordValid = await bcrypt.compare(
      password,
      foundUsername.password
    );
    if (isPasswordValid === false) {
      res.render("auth/login.hbs", { errorMessage: "Contraseña incorrecta" });
      return;
    }
    // Abrir sesión de usuario
    req.session.user = {
      _id: foundUsername._id,
      username: foundUsername.username,
    };

    req.session.save(() => {
      //Una vez inicia sesión le envíamos a Inicio
      res.redirect("/");
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
