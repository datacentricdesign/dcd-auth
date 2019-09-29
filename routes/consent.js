"use strict";

// Read scopes
const fs = require("fs");
const scopeLib = JSON.parse(fs.readFileSync("scopes.json", "utf8"));
// Whitelist of app to skip consent
const firstPartyApps = (process.env.FIRST_PARTY_APPS || "").split(",");

const API = require("./API");
const url = require("url");
const hydra = require("../services/hydra");
const util = require("../services/util");

class ConsentAPI extends API {
  init() {
    /**
     * Consent - display
     */
    this.router.get("/", this.csrfProtection, function(req, res, next) {
      // Parses the URL query
      const query = url.parse(req.url, true).query;

      // The challenge is used to fetch information
      // about the consent request from ORY Hydra.
      const challenge = query.consent_challenge;

      hydra
        .getConsentRequest(challenge)
        // This will be called if the HTTP request was successful
        .then(response => {
          // If a user has granted this application the requested scope,
          // hydra will tell us to not show the UI.
          if (
            response.skip ||
            firstPartyApps.includes(response.client.client_id)
          ) {
            // You can apply logic here, for example grant
            // another scope, or do whatever...

            // Now it's time to grant the consent request. You could also
            // deny the request if something went terribly wrong
            return hydra
              .acceptConsentRequest(challenge, {
                // We can grant all scopes that have been requested,
                // hydra already checked for us that no additional scopes
                // are requested accidentally.
                grant_scope: response.requested_scope,

                // The session allows us to set session data
                // for id and access tokens
                session: {
                  // This data will be available when introspecting
                  // the token. Try to avoid sensitive information here,
                  // unless you limit who can introspect tokens.
                  // access_token: { foo: 'bar' },

                  // This data will be available in the ID token.
                  id_token: util.buildIDToken(
                    response.requested_scope,
                    response.subject
                  )
                }
              })
              .then(response => {
                // All we need to do now is to redirect the
                // user back to hydra!
                res.redirect(response.redirect_to);
              });
          }

          const scopes = response.requested_scope;
          const detailedScopes = buildDetailedScopes(scopes);

          // If consent can't be skipped we MUST show the consent UI.
          res.render("consent", {
            baseUrl: this.baseUrl,
            csrfToken: req.csrfToken(),
            challenge: challenge,
            requested_scope: detailedScopes,
            user: response.subject.replace("dcd:persons:", ""),
            client: response.client
          });
        })
        // This will handle any error that happens
        // when making HTTP calls to hydra
        .catch(error => next(error));
    });

    /**
     * Consent - Validation
     */
    this.router.post("/", this.csrfProtection, (req, res, next) => {
      // The challenge is now a hidden input field, so let's take it
      // from the request body instead
      const challenge = req.body.challenge;

      // Let's see if the user decided to accept or reject the consent request..
      if (req.body.submit === "Deny access") {
        // Looks like the consent request was denied by the user
        return (
          hydra
            .rejectConsentRequest(challenge, {
              error: "access_denied",
              error_description: "The resource owner denied the request"
            })
            .then(response => {
              // All we need to do now is to redirect
              // the browser back to hydra!
              res.redirect(response.redirect_to);
            })
            // This will handle any error that happens
            // when making HTTP calls to hydra
            .catch(error => next(error))
        );
      }

      let grant_scope = req.body.grant_scope;
      if (!Array.isArray(grant_scope)) {
        grant_scope = [grant_scope];
      }
      // Seems like the user authenticated! Let's tell hydra...
      hydra
        .acceptConsentRequest(challenge, {
          // We can grant all scopes that have been requested,
          // hydra already checked for us that no additional scopes
          // are requested accidentally.
          grant_scope: grant_scope,

          // The session allows us to set session data for id and access tokens
          session: {
            // This data will be available when introspecting the token.
            // Try to avoid sensitive information here,
            // unless you limit who can introspect tokens.
            // access_token: { foo: 'bar' },

            // This data will be available in the ID token.
            id_token: util.buildIDToken(grant_scope, req.body.user)
          },

          // This tells hydra to remember this consent request and allow the
          // same client to request the same
          // scopes from the same user, without showing the UI, in the future.
          remember: Boolean(req.body.remember),

          // When this "remember" session expires, in seconds. Set this to 0
          // so it will never expire.
          remember_for: 3600
        })
        .then(response => {
          console.log("consent valid response:");
          console.log(response);
          // All we need to do now is to redirect the user back to hydra!
          res.redirect(response.redirect_to);
        })
        // This will handle any error that happens
        // when making HTTP calls to hydra
        .catch(error => next(error));
    });
  }
}

function buildDetailedScopes(scopes) {
  const detailedScopes = [];
  for (let key in scopes) {
    if (scopeLib[scopes[key]]) {
      detailedScopes.push(scopeLib[scopes[key]]);
    } else {
      detailedScopes.push({
        id: scopes[key],
        name: scopes[key],
        desc: ""
      });
    }
  }
  return detailedScopes;
}

module.exports = ConsentAPI;
