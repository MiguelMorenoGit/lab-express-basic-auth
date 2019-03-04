const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const mongoose = require('mongoose');

// para inicar el mongoose session esto esta cojido del cheasheet m2/express-app/session.js
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);

// para meter flash
const flash = require('connect-flash');
const hbs = require('hbs');// para las partials

// indicamos las rutas
const indexRouter = require('./routes/index');
const authRouter = require('./routes/auth');

const app = express();

// necesario para la session ------ despues de insertar este codigo del cheat sheet instalar ne el terminal el session, arriba del cheetsheet
app.use(session({
  store: new MongoStore({
    mongooseConnection: mongoose.connection,
    ttl: 24 * 60 * 60 // 1 day
  }),
  secret: 'some-string',
  resave: true,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(flash()); // hay que ponerlo despues de session pues flash depende de el

mongoose.connect('mongodb://localhost/basic-auth', {
  keepAlive: true,
  useNewUrlParser: true,
  reconnectTries: Number.MAX_VALUE
});
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
hbs.registerPartials(path.join(__dirname, '/views/partials'));

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// para usar las SESSION sacado del cheat sheet
app.use((req, res, next) => {
  app.locals.currentUser = req.session.currentUser;
  next();
});

app.use('/', indexRouter);
app.use('/auth', authRouter);

// -- 404 and error handler

// NOTE: requires a views/not-found.ejs template
app.use((req, res, next) => {
  res.status(404);
  res.render('not-found');
});

// NOTE: requires a views/error.ejs template
app.use((err, req, res, next) => {
  // always log the error
  console.error('ERROR', req.method, req.path, err);

  // only render if the error ocurred before sending the response
  if (!res.headersSent) {
    res.status(500);
    res.render('error');
  }
});

module.exports = app;
