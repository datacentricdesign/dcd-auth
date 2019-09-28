"use strict";

const API = require("./API");
const url = require("url");
const hydra = require("../services/hydra");
const util = require("../services/util");

class SignInAPI extends API {
  init() {
    /**
     * Sign in - Display
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
            // You can apply logic here, for example update
            // the number of times the user logged in.
            // ...

            // Now it's time to grant the login request. You could also
            // deny the request if something went terribly wrong
            // (e.g. your arch-enemy logging in...)
            return hydra
              .acceptLoginRequest(challenge, {
                // All we need to do is to confirm that we indeed
                // want to log in the user.
                subject: response.subject
              })
              .then(function(response) {
                // All we need to do now is to redirect the user
                // back to hydra!
                res.redirect(response.redirect_to);
              });
          }

          // If authentication can't be skipped
          // we MUST show the login UI.
          res.render("signin", {
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
     * Sign in - Validation
     */
    this.router.post("/", this.csrfProtection, (req, res, next) => {
      // The challenge is now a hidden input field,
      // so let's take it from the request body instead
      const challenge = req.body.challenge;
      const url = process.env.API_URL + "/persons/" + req.body.email + "/check";
      const body = {
        password: req.body.password
      };
      this.auth.refresh().then(() => {
        this.auth
          .authorisedRequest("POST", url, body)
          .then(result => {
            // Tell hydra to login this user
            if (result.person !== undefined && result.person.valid) {
              req.subject = req.body.email;
              util.login(req, res, next);
            } else {
              // Looks like the user provided invalid credentials,
              // let's show the ui again...
              res.render("signin", {
                baseUrl: this.baseUrl,
                csrfToken: req.csrfToken(),
                challenge: challenge,
                error: {
                  message: "The email / password combination is not correct"
                }
              });
            }
          })
          .catch(error => next(error));
      });
    });
  }
}

module.exports = SignInAPI;
