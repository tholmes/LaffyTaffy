/*
 * Copyright Utah State University Research Foundation.
 * All rights reserved except as specified below.
 * This information is protected by a Non-Disclosure/Government Purpose
 * License Agreement and is authorized only for United States Federal
 * Government use.
 * This information may be subject to export control.
 */
"use strict";
const bodyParser = require("body-parser");
const passport = require("passport");
const express = require("express");
const fs = require("fs");
const _ = require("lodash");
const LocalStrategy = require("passport-local").Strategy;
const OpenSSOStrategy = require("../lib/authentication/openssoStrategy");
const LdapStrategy = require("passport-ldapauth");
const opensso = require("../lib/authentication/opensso");
const serverConfig = require("../lib/serverConfig");
const configDatabase = require("../lib/configDatabase");
const logger = require("../lib/logger");
const cryptUtil = require("../lib/cryptography");
const router = express.Router();
const jsonParser = bodyParser.json();
const authenticationStrategy = serverConfig.get("web:authenticationStrategy");
const pkiStrategy = require("../lib/authentication/strategies/pki");

var users = [];
var acceptedGroups = _.reduce(serverConfig.get("web:groups"), function (result, value) {
  return result.concat(value);
}, []);
var ca = [];

try {
  ca = serverConfig.get("web:opensso:ca").map(fs.readFileSync);
} catch (err) {
  logger.error("[Login] Could not read certificate authority files: " + serverConfig.get("web:opensso:ca") + " " + err);
}

function transformPositions(positions, pre) {
  if (!_.isArray(positions)) {
    return [positions.substr(pre)];
  }
  return positions.map(function (position) {
    return position.substr(pre);
  });
}

passport.serializeUser(function (user, done) {
  if (authenticationStrategy === "local") {
    done(null, user.guid);
  } else {
    done(null, user.uid);
  }
});

passport.deserializeUser(function (id, done) {
  var user;
  if (authenticationStrategy === "local") {
    user = configDatabase.getDataById("users", id);
  } else {
    user = _.find(users, { uid: id });
  }
  if (user) {
    done(null, user);
  } else {
    done(new Error("Invalid User Session"), null);
  }
});

function groupAttribute(attrs) {
  var groupAttr = serverConfig.get("web:groups").groupAttribute;
  if (!groupAttr) {
    // if no groupAttribute parameter set, use the "position" attribute
    // this attribute has a 2 character "site" id that we strip off
    //(could be used in the future for more granular authorizationing)
    return transformPositions(attrs.position, 2);
  }
  // if the groupAttribute parameter is set, use that attribute without modification
  return transformPositions(attrs[groupAttr], 0);
}

if (authenticationStrategy === "opensso") {
  passport.use("opensso", new OpenSSOStrategy(
    {
      protocol: serverConfig.get("web:opensso:protocol"),
      host: serverConfig.get("web:opensso:host"),
      port: serverConfig.get("web:opensso:port"),
      path: serverConfig.get("web:opensso:path"),
      realm: serverConfig.get("web:opensso:realm"),
      cookieName: serverConfig.get("web:opensso:cookieName"),
      ca: ca,
      callbackPath: "/log/in"
    },
    function (attrs, done) {
      var user =
      {
        uid: attrs.uid,
        sn: attrs.sn,
        cn: attrs.cn,
        givenname: attrs.givenname,
        token: attrs.tokenId,
        groups: groupAttribute(attrs)
      };

      logger.debug(user);

      if (_.intersection(acceptedGroups, user.groups).length > 0) {
        logger.info("[Login] Success, UID:" + user.uid + " Groups: " + user.groups.join(", "));
        users.push(user);
        done(null, user);
      } else {
        logger.error("[Login] Insufficient permissions, UID: " + user.uid + " Groups: " + user.groups.join(", "));
        done(null, false);
      }
    }
  ));

  router.get("/in", passport.authenticate("opensso", {
    successRedirect: "/index.html",
    failureRedirect: opensso.getLoginUrl()
  }));
  router.get("/out", function (req, res) {
    logger.apiInfo(req, {
      component: "Logout",
      action: "Logout",
      message: ""
    });
    res.redirect(opensso.getLogoutUrl());
    _.remove(users, function (user) { return req.user.uid === user.uid; });
    req.session.destroy(_.noop);
  });
} //end opensso

router.get("/pki", function (req, res) {
  res.json({ enabled: pkiStrategy.enabled});
});

if (pkiStrategy.enabled) {
  passport.use(pkiStrategy.get());
  router.post("/in", jsonParser, function (req, res, next) {
    if (req.body.pki) {
      pkiStrategy
        .login(req)
        .then(function () {
          passport.authenticate(pkiStrategy.name, function (err, user) {
            if (err) {
              logger.warn("[Login] " + err.message);
              return res.redirect(401, "/login.html");
            }
            if (!user) {
              return next(new Error("Invalid credentials, unable to authenticate"));
            }
            req.logIn(user, function (err) {
              if (err) { return next(err); }
              logger.info("[Login] User logged in: " + user.uid);
              return res.redirect("/index.html");
            });
          })(req, res, next);
        });
    } else {
      return next();
    }
  });
} //end PKI


if (authenticationStrategy === "ldap") {
  var serverConfigVal = serverConfig.get("web:ldap");
  // Configure the 3rd party lib to use DDE's logging system
  serverConfigVal.log4js = logger;
  // Decrypt the bind password
  serverConfigVal.bindCredentials = cryptUtil.decrypt(serverConfigVal.bindCredentials);
  // Load in any CAs
  if (serverConfigVal.ca) {
    serverConfigVal.tlsOptions = { ca: serverConfigVal.ca.map(function (ca) {
      return fs.readFileSync(ca);
    })};
  }
  passport.use("ldap", new LdapStrategy(
    {
      server: serverConfigVal
    },
    function (attrs, done) {
      var user =
      {
        uid: attrs.uid,
        sn: attrs.sn,
        cn: attrs.cn,
        givenname: attrs.givenName,
        groups: groupAttribute(attrs)
      };

      logger.debug(user);

      if (_.intersection(acceptedGroups, user.groups).length > 0) {
        logger.info("[Login] Success, UID: " + user.uid + " Groups: " + user.groups.join(", "));
        users.push(user);
        done(null, user);
      } else {
        logger.error("[Login] Insufficient permissions, UID: " + user.uid + " Groups: " + user.groups.join(", "));
        done(null, false);
      }
    }
  ));

  router.post("/in", jsonParser, passport.authenticate("ldap", {
    successRedirect: "/index.html",
    failureRedirect: "/login.html"
  }));
  router.get("/in", function (req, res) {
    res.redirect("/login.html?message=" + req.session.message || "");
  });
  router.get("/out", function (req, res) {
    logger.apiInfo(req, {
      component: "Logout",
      action: "Logout",
      message: ""
    });
    res.redirect("/login.html");
    _.remove(users, function (user) { return req.user.uid === user.uid; });
    req.session.destroy(_.noop);
  });
} //end ldap

if (authenticationStrategy === "local") {
  passport.use(new LocalStrategy(
    function (username, password, done) {
      var user = _.find(configDatabase.getData("users"), { uid: username });
      if (user) {
        cryptUtil.hash(password, user.salt, function (err, hashedPassword) {
          var now = new Date();
          if (err) {
            done(new Error("An error occurred while processing the login request"));
            logger.error("[Login] Error: " + err.stack);
          }
          if (hashedPassword === user.password) {
            if (user.passwordExpiration && user.passwordExpiration < now.getTime()) {
              done(new Error("Password expired")); //This is not sent to the client but is logged
              return;
            }
            done(null, user);
            return;
          }
          done(new Error("Invalid username or password"));
        });
        return;
      }
      done(new Error("Invalid username or password"));
    }
  ));
  router.post("/in", jsonParser, function (req, res, next) {
    passport.authenticate("local", function (err, user) {
      if (err) {
        logger.warn("[Login] " + err.message);
        return res.redirect(401, "/login.html");
      }
      req.logIn(user, function (err) {
        if (err) { return next(err); }
        logger.info("[Login] User logged in: " + user.uid);
        return res.redirect("/index.html");
      });
    })(req, res, next);
  });
  router.get("/in", function (req, res) {
    res.redirect("/login.html?message=" + req.session.message || "");
  });
  router.get("/out", function (req, res) {
    if (req.user) {
      logger.apiInfo(req, {
        component: "Logout",
        action: "Logout",
        message: ""
      });
    }
    res.redirect("/login.html");
    req.session.destroy(_.noop);
  });
} //end local

module.exports = router;
