module.exports = {
  //  1 // requireAnon comprobara si actualmente hay algun usuario logeado
  requireAnon (req, res, next) {
    if (req.session.currentUser) {
      res.redirect('/');
      return;
    }
    next(); // si no existe un usuario logeado la funcion continuara
  },

  // 2 // requireFields comprobara que ambos campos esten rellenos para completar el form
  requireFields (req, res, next) {
    const { username, password } = req.body;
    if (!password || !username) { //  si falta alguno de los campos
      req.flash('validation', 'username or password missing'); // mostrara el mensaje de error que le indicamos
      res.redirect(`/auth${req.path}`); // y te devolvera a la misma pagina dnd estes, signup o login
      return;
    }
    next(); // si los dos campos estan rellenos la funcion continuara
  }
};
