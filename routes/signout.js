"use strict";

const API = require("./API");
const url = require("url");
const hydra = require("../services/hydra");

class SignOutAPI extends API {
  init() {
    this.router.get("/", this.csrfProtection, function(req, res, next) {
      // Parses the URL query
      const query = url.parse(req.url, true).query;

      // The challenge is used to fetch information about the logout request from ORY Hydra.
      const challenge = query.logout_challenge;

      hydra
        .getLogoutRequest(challenge)
        // This will be called if the HTTP request was successful
        .then(response => {
          // Here we have access to e.g. response.subject, response.sid, ...

          // The most secure way to perform a logout request is by asking the user if he/she really want to log out.
          res.render("logout", {
            csrfToken: req.csrfToken(),
            challenge: challenge
          });
        })
        // This will handle any error that happens when making HTTP calls to hydra
        .catch(error => next(error));
    });

    this.router.post("/", this.csrfProtection, function(req, res, next) {
      // The challenge is now a hidden input field, so let's take it from the request body instead
      const challenge = req.body.challenge;

      if (req.body.submit === "No") {
        return (
          hydra
            .rejectLogoutRequest(challenge)
            .then(function() {
              // The user did not want to log out. Let's redirect him back somewhere or do something else.
              res.redirect("https://dwd.tudelft.nl");
            })
            // This will handle any error that happens when making HTTP calls to hydra
            .catch(function(error) {
              next(error);
            })
        );
      }

      // The user agreed to log out, let's accept the logout request.
      hydra
        .acceptLogoutRequest(challenge)
        .then(function(response) {
          // All we need to do now is to redirect the user back to hydra!
          res.redirect(response.redirect_to);
        })
        // This will handle any error that happens when making HTTP calls to hydra
        .catch(error => next(error));
    });
  }
}

module.exports = SignOutAPI;
