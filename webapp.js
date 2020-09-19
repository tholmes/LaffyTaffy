/*
 * Copyright Utah State University Research Foundation.
 * All rights reserved except as specified below.
 * This information is protected by a Non-Disclosure/Government Purpose
 * License Agreement and is authorized only for United States Federal
 * Government use.
 * This information may be subject to export control.
 */
"use strict";
const crypto = require("crypto");
const domain = require("domain");
const express = require("express");
const timeout = require("connect-timeout");
const http = require("http");
const https = require("https");
const logger = require("./logger");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const passport = require("passport");
const fs = require("fs");
const path = require("path");
const routes = require("../routes");
const serverConfig = require("./serverConfig");
const permissions = require("./permissions");
const _ = require("lodash");
const utilities = require("./util");

var app = express();
var server;
var httpsOpts = {};
var sessionOpts = {
  cookie: {
    secure: serverConfig.get("web:protocol") === "https",
    httpOnly: true
  },
  name: "dde.session",
  resave: true,
  rolling: true,
  saveUninitialized: true,
  secret: crypto.randomBytes(256).toString()
};
var hasLocalAccounts = serverConfig.get("web:authenticationStrategy") === "local" ||
  serverConfig.get("web:pki:enabled");

if (hasLocalAccounts) {
  sessionOpts.cookie.maxAge = parseFloat(serverConfig.get("web:sessionTimeout")) * 60000;
}

// custom middleware
function enterDomain(req, res, next) {
  var requestDomain = domain.create();
  requestDomain.add(req);
  requestDomain.add(res);
  requestDomain.on("error", function (err) {
    logger.error("Error: " + err.stack);
    res.status(500).json({ error: "There was a domain error." });
  });
  requestDomain.enter();
  next();
}
function preLoginFile(file) {
  return function (req, res) {
    res.sendFile(path.join(__dirname, "../public", file));
  };
}
function checkAuthentication(req, res, next) {
  var contentType;
  if (req.isAuthenticated()) {
    return next();
  }
  contentType = req.headers["content-type"];
  if (contentType && _.includes(contentType, "json")) {
    res.status(401).json({});
  } else {
    req.session.message = "Session timed out";
    res.redirect("/log/in");
  }
}
function checkErrors(err, req, res, next) {
  if (err) {
    logger.apiError(req, err);
    res.status(400).json({ error: err.message });
  } else {
    return next();
  }
}
function index(req, res) {
  res.render("index", {
    isAdmin: permissions.isAdmin(req.user),
    displayName: req.user.givenname + " " + req.user.sn,
    hasLocalAccounts: hasLocalAccounts,
    hasUid: !_.isEmpty(req.user.uid)
  });
}
function configure(req, res) {
  res.render("configure", {
    isAdmin: permissions.isAdmin(req.user)
  });
}
function users(req, res) {
  res.render("users", {
    isAdmin: permissions.isAdmin(req.user),
    hasLocalAccounts: hasLocalAccounts
  });
}
function jobDisplay(req, res) {
  res.render("jobDisplay", {
    isJobControl: permissions.isJobControl(req.user)
  });
}
function notFound(req, res) {
  logger.apiError(req, new Error("Page not found"));
  res.status(404).json({ error: "Page not found." });
}

// server configuration
if (serverConfig.get("web:protocol") === "https") {
  if (serverConfig.get("web:https:pfx")) {
    httpsOpts.pfx = fs.readFileSync(serverConfig.get("web:https:pfx"));
  } else if (serverConfig.get("web:https:certificate")) {
    httpsOpts.cert = fs.readFileSync(serverConfig.get("web:https:certificate"));
    httpsOpts.key = fs.readFileSync(serverConfig.get("web:https:key"));
  }
  if (serverConfig.get("web:pki:enabled")) {
    httpsOpts.ca = utilities.getCertificates(serverConfig.get("web:pki:caPath"));
    httpsOpts.crl = utilities.getCertificates(serverConfig.get("web:pki:crlPath"));
  }
  httpsOpts.passphrase = serverConfig.get("web:https:passphrase");
  server = https.createServer(httpsOpts, app);
} else {
  server = http.createServer(app);
}
// Reduce the default Node.js socket timeout from 2 minutes to something smaller
// This helps with situations we have seen where the web browser locks out because
// it has hit the connection limit
// https://nodejs.org/api/http.html#http_server_timeout
server.timeout = serverConfig.get("web:serverTimeoutInMs") || 35000;
server.maxConnections = serverConfig.get("web:maxConnections");
server.listen(serverConfig.get("web:port"), serverConfig.get("web:host"));
// Need to initialize the socket.io after the server is listening.
require("./socketHandler").initSocket(server);

app.engine(".html", require("ejs").__express);// eslint-disable-line no-underscore-dangle
app.set("views", path.join(__dirname, "../views"));
app.set("view engine", "html");
app.disable("x-powered-by");

// TRICKY: Set a max timeout for an API request so that we don't exceed
// the max 6 open connections limit on the browser. When this
// happens the browser appears to freeze up because the browser can't request
// more pages from the web server.
var apiTimeout = serverConfig.get("web:apiTimeout") || "30s"; // default to 30 seconds
app.use(timeout(apiTimeout));

// server middleware stack
app.use(enterDomain);
app.use(cookieParser());
app.use(session(sessionOpts));
app.use(passport.initialize());
app.use(passport.session());
app.use(logger.connectLogger());
if (hasLocalAccounts || serverConfig.get("web:authenticationStrategy") === "ldap") {
  app.use("/login.html", preLoginFile("/shared/login.html"));
  app.use("/js/main.min.js", preLoginFile("/js/main.min.js"));
  app.use("/css/main-default.min.css", preLoginFile("/css/main-default.min.css"));
  app.use("/css/bootstrap-default.min.css", preLoginFile("/css/bootstrap-default.min.css"));
  app.use("/js/vendor.min.js", preLoginFile("/js/vendor.min.js"));
  app.use("/css/vendor.min.css", preLoginFile("/css/vendor.min.css"));
  app.use("/shared/spinner.html", preLoginFile("/shared/spinner.html"));
  app.use("/images/favicon.ico", preLoginFile("/images/favicon.ico"));
  app.use("/images/logo.png", preLoginFile("/images/logo.png"));
  app.use("/fonts/fontawesome-webfont.eot", preLoginFile("/fonts/fontawesome-webfont.eot"));
  app.use("/fonts/fontawesome-webfont.svg", preLoginFile("/fonts/fontawesome-webfont.svg"));
  app.use("/fonts/fontawesome-webfont.ttf", preLoginFile("/fonts/fontawesome-webfont.ttf"));
  app.use("/fonts/fontawesome-webfont.woff", preLoginFile("/fonts/fontawesome-webfont.woff"));
  app.use("/fonts/fontawesome-webfont.woff2", preLoginFile("/fonts/fontawesome-webfont.woff2"));
}
app.use("/log", routes.login);
app.use(checkAuthentication);
app.use(checkErrors);
app.get("/", index);
app.get("/index.html", index);
app.get("/app/jobs/jobDisplay.html", jobDisplay);
app.get("/app/configure/configure.html", configure);

app.use("/v1", routes.v1);
app.use("/", routes.v1);

if (hasLocalAccounts) {
  app.get("/app/users/manageUsers.html", users);
}

app.use(checkErrors);
app.use(express.static(path.join(__dirname, "../public")));
app.use(notFound);

// exports
module.exports = app;
