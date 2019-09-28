"use strict";

const hydra = require("./hydra");

function util(req, res, next) {
  // Seems like the user authenticated! Let's tell hydra...
  hydra
    .acceptLoginRequest(req.body.challenge, {
      // Subject is an alias for user ID. A subject can be a random string,
      // a UUID, an email address, ....
      subject: "dcd:persons:" + req.subject,

      // This tells hydra to remember the browser and automatically
      // authenticate the user in future requests. This will
      // set the "skip" parameter in the other
      // route to true on subsequent requests!
      remember: Boolean(req.body.remember),

      // When the session expires, in seconds. Set this to 0
      // so it will never expire.
      remember_for: 3600

      // Sets which "level" (e.g. 2-factor authentication) of
      // authentication the user has. The value is really arbitrary
      // and optional. In the context of OpenID Connect, a value
      // of 0 indicates the lowest authorization level.
      // acr: '0',
    })
    .then(response => {
      // req.session.subject = req.subject;
      // All we need to do now is to redirect the
      // user back to hydra!
      res.redirect(response.redirect_to);
    })
    // This will handle any error that happens when making
    // HTTP calls to hydra
    .catch(error => next(error));

  // You could also deny the login request which tells hydra
  // that no one authenticated!
  // hydra.rejectLoginRequest(challenge, {
  //   error: 'invalid_request',
  //   error_description: 'The user did something stupid...'
  // })
  //   .then(function (response) {
  //     // All we need to do now is to
  //     // redirect the browser back to hydra!
  //     res.redirect(response.redirect_to);
  //   })
  //   // This will handle any error that happens when making
  //   // HTTP calls to hydra
  //   .catch(function (error) {
  //     next(error);
  //   });
}

exports.login = util;

function getPersonDetails(subject) {
  const url = process.env.API_URL + "/persons/" + subject;
  return this.auth.refresh().then(() => {
    return this.auth.authorisedRequest("GET", url);
  });
}

exports.getPersonDetails = getPersonDetails;

function buildIDToken(grant_scope, subject) {
  console.log("build id token: " + subject);
  const username = subject.replace("dcd:persons:", "");
  const idToken = {};
  // This is the openid 'profile' scope which should include
  // some user profile data. (optional)
  if (grant_scope.indexOf("profile") > 0) {
    idToken.id = username;
    idToken.sub = username;
    idToken.name = username;
    idToken.teams = "1";
    idToken.given_name = username;
    idToken.family_name = "";
    idToken.profile = "";
  }

  // This is to fulfill the openid 'email' scope which returns
  // the user's email address. (optional)
  if (grant_scope.indexOf("email") > 0) {
    idToken.email = username;
    idToken.email_verified = true;
  }

  if (grant_scope.indexOf("phone") > 0) {
    idToken.phone_number = "";
    idToken.phone_verified = false;
  }
  return idToken;
}

exports.buildIDToken = buildIDToken;
