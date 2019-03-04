const express = require('express');
const bcrypt = require('bcrypt'); // para encriptar el paswword  parte 1
const router = express.Router();

const User = require('../models/User');
const { requireAnon, requireFields } = require('../middlewares/auth');

const saltRounds = 10; // para encriptar el paswword parte 2

//  ---- SIGNUP ----

//  1 // DECLARAMOS EL GET,  en la ruta/signup, renderizamos /auth/signup
//  2 // solo renderizamos la pagina sign up si no hay un usuario logeado, lo comprobamos con el middleware requireAnon que nos hemos creado
router.get('/signup', requireAnon, (req, res, next) => {
  const data = {
    messages: req.flash('validation')
  };
  res.render('auth/signup', data);
});

//  1 // DECLARAMOS EL POST,  en la ruta/signup, renderizamos /auth/signup
//  2 // antes de todo comprobamos que no haya usuario loegado ni qu eesten vacio ningun campo con requireAnon y requireFields

router.post('/signup', requireAnon, requireFields, async (req, res, next) => {
  const { username, password } = req.body; //  3 // obtenemos los datos del form con req.body
  try {
    const result = await User.findOne({ username }); //  3.1 // obtenemos el username
    //  4   // comprobamos si ya existe antes de aceptarlo
    if (result) {
      req.flash('validation', 'this username is taken');
      res.redirect('/auth/signup');
      return;
    }
    // Encryptar password----vamos al cheetsheet /m2/express-apps/bcrypt.js
    const salt = bcrypt.genSaltSync(saltRounds);
    const hashedPassword = bcrypt.hashSync(password, salt);
    // Crear el usuario
    const newUser = {
      username,
      password: hashedPassword
    };
    const createdUser = await User.create(newUser);
    // guardamos el usuario en la session
    req.session.currentUser = createdUser;
    // Redirigimos para la Homepage
    res.redirect('/');
  } catch (error) {
    next(error);
  }
});

//  ---- LOGIN ----

//  1 // DECLARAMOS EL GET,  en la ruta/signup, renderizamos /auth/login
//  2 // solo renderizamos la pagina sign up si no hay un usuario logeado, lo comprobamos con el middleware requireAnon que nos hemos creado

router.get('/login', requireAnon, (req, res, next) => {
  const data = {
    messages: req.flash('validation')
  };
  res.render('auth/login', data);
});

//  1 // DECLARAMOS EL POST,  en la ruta/signup, renderizamos /auth/login
//  2 // antes de todo comprobamos que no haya usuario logado ni que este vacio ningun campo con requireAnon y requireFields

router.post('/login', requireAnon, requireFields, async (req, res, next) => {
  //  Extraer informacion del body
  const { username, password } = req.body;

  try {
    //  comprobar que el usuario existe
    const user = await User.findOne({ username });
    if (!user) {
      req.flash('validation', 'User or password incorrect');
      res.redirect('/auth/login');
      return;
    }
    //  comprobar la contraseña
    if (bcrypt.compareSync(password, user.password)) {
      //  guardar la session
      req.session.currentUser = user;
      //  redirigir
      res.redirect('/');
    } else {
      req.flash('validation', 'User or password incorrect');
      res.redirect('/auth/login');
    }
  } catch (error) {
    next(error);
  }
});

//  ---- LOGOUT ----

router.post('/logout', async (req, res, next) => {
  if (!req.session.currentUser) {
    res.redirect('/');
    return;
  }
  delete req.session.currentUser;

  res.redirect('/');
});

module.exports = router;
