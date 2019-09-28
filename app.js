const express = require("express");
const path = require("path");
const favicon = require("serve-favicon");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");

const DCDError = require("dcd-model/lib/Error");

// Setting the logs
const log4js = require("log4js");
const logger = log4js.getLogger("[dcd-app-identity-provider:app]");
logger.level = process.env.LOG_LEVEL || "INFO";

const app = express();

const baseUrl = process.env.BASE_URL || "/auth";

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

app.use(favicon(path.join(__dirname, "public", "img/logo/favicon.ico")));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(
  baseUrl,
  express.static(path.join(__dirname, "public"), {
    etag: false,
    maxAge: 100
  })
);

const Auth = require("dcd-model/lib/Auth");
const auth = new Auth();

const ConsentAPI = require("./routes/consent");
const consent = new ConsentAPI(auth);
app.use(baseUrl + "/consent", consent.router);

const SignInAPI = require("./routes/signin");
const signin = new SignInAPI(auth);
app.use(baseUrl + "/signin", signin.router);

const SignUpAPI = require("./routes/signup");
const signup = new SignUpAPI(auth);
app.use(baseUrl + "/signup", signup.router);

const SignOutAPI = require("./routes/signout");
const signout = new SignOutAPI(auth);
app.use(baseUrl + "/signout", signout.router);

/**
 * Catch 404 and forward to error handler
 */
app.use((request, response, next) => {
  next(new DCDError(404, "Path not found: " + request.path));
});

/**
 * Error handler
 */
app.use((error, request, response, next) => {
  if (error instanceof DCDError) {
    console.error(JSON.stringify(error));
  } else {
    console.error(JSON.stringify(error, Object.getOwnPropertyNames(error)));
  }
  response.status(error.status || 500);
  response.render("signin", {
    baseUrl: baseUrl,
    error: error
  });
});

module.exports = app;
