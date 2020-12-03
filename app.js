var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var logger = require('morgan');

var dotenv = require('dotenv');
var passport = require('passport');
var Strategy = require('passport-saml').Strategy;
var MultiSamlStrategy = require('passport-saml/multiSamlStrategy');
var session = require('express-session');

// passport-saml setup
dotenv.config();
var strategy = new Strategy(
  {
    path: '/login/callback',
    entryPoint: process.env.SAML_ENTRY_POINT,
    issuer: process.env.SAML_ISSUER,
    cert: process.env.SAML_CERT || null
  },
  function(profile, done) {
    console.log(JSON.stringify(profile, null, 2));
    return done(null, {
      name_id: profile.nameID,
    });
  }
);
var multiSamlStrategy = new MultiSamlStrategy(
  {
    getSamlOptions: (req, done) => {
      return done(null, {
        path: '/login/callback',
        entryPoint: process.env.SAML_ENTRY_POINT,
        issuer: process.env.SAML_ISSUER,
        cert: process.env.SAML_CERT || null,
      });
    }
  },
  function(profile, done) {
    console.log(JSON.stringify(profile, null, 2));
    return done(null, {
      name_id: profile.nameID,
    });
  }
);
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});
passport.use(multiSamlStrategy);

// express setup
var app = express();
app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 60 * 1000
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// routing setup
app.get('/', function(req, res, _) {
  res.render('index', {
    title: 'Test Application for express with passport-saml',
    username: req.user ? req.user.name_id : null
  });
});

app.get('/login',
  passport.authenticate('saml', {
    successRedirect: '/',
    failureRedirect: '/login'
  })
);
app.post('/login/callback',
  passport.authenticate('saml', {
    failureRedirect: '/',
    failureFlash: true
  }),
  function (req, res) {
    console.log(req.user)
    res.redirect('/');
  }
);

app.get('/logout', function(req, res){
  strategy.logout(req, function(err, request){
    if(!err) res.redirect(request);
  });
});
app.post('/logout/callback', function(req, res){
  req.logout();
  res.redirect('/');
});

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
