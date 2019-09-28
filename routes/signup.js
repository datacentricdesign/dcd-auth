"use strict";

const API = require("./API");
const url = require("url");
const hydra = require("./services/hydra");
const util = require("./services/util");

class SignUpAPI extends API {
  init() {
    /**
     * Sign up - Display
     */
    this.router.get("/", this.csrfProtection, (req, res, next) => {
      // Parses the URL query
      const query = url.parse(req.url, true).query;

      // The challenge is used to fetch information
      // about the login request from ORY Hydra.
      const challenge = query.login_challenge;

      hydra
        .getLoginRequest(challenge)
        // This will be called if the HTTP request was successful
        .then(function(response) {
          // If hydra was already able to authenticate the user,
          // skip will be true and we do not need to re-authenticate
          // the user.
          if (response.skip) {
            // Now it's time to grant the login request. You could also
            // deny the request if something went terribly wrong
            return hydra
              .acceptLoginRequest(challenge, {
                // All we need to do is to confirm that we indeed
                // want to log in the user.
                subject: response.subject
              })
              .then(response => {
                // All we need to do now is to redirect the user
                // back to hydra!
                res.redirect(response.redirect_to);
              });
          }

          // If authentication can't be skipped
          // we MUST show the sign up UI.
          res.render("signup", {
            baseUrl: this.baseUrl,
            csrfToken: req.csrfToken(),
            challenge: challenge
          });
        })
        // This will handle any error that happens
        // when making HTTP calls to hydra
        .catch(error => next(error));
    });

    /**
     * Sign up - Validation
     */
    this.router.post("/", this.csrfProtection, (req, res, next) => {
      const url = process.env.API_URL + "/persons";
      const body = {
        id: req.body.email,
        name: req.body.name,
        password: req.body.password
      };
      this.auth
        .refresh()
        .then(() => {
          return this.auth.authorisedRequest("POST", url, body);
        })
        .then(result => {
          req.subject = result.personId;
          util.login(req, res, next);
        })
        .catch(error => {
          res.render("signup", {
            baseUrl: this.baseUrl,
            csrfToken: req.csrfToken(),
            challenge: req.body.challenge,
            error: error.message
          });
        });
    });
  }
}

module.exports = SignUpAPI;
