const express = require('express');
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

const app = express();

const baseUrl = process.env.BASE_URL || '/auth';

// Sets up csrf protection
const csrf = require('csurf');
const csrfProtection = csrf({cookie: true});

const url = require('url');
const hydra = require('./services/hydra');

const Auth = require('dcd-model/lib/Auth');
const auth = new Auth();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
app.use(cookieParser());

const session = require('express-session');
app.set('trust proxy', 1); // trust first proxy
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));

app.use(baseUrl, express.static(path.join(__dirname, 'public'), {
    etag: false,
    maxAge: 100,
}));

app.get(baseUrl + '/', function(req, res) {
    res.render('index');
});


/**
 * Consent - display
 */
app.get(baseUrl + '/consent', csrfProtection, function(req, res, next) {
    // Parses the URL query
    const query = url.parse(req.url, true).query;

    // The challenge is used to fetch information
    // about the consent request from ORY Hydra.
    const challenge = query.consent_challenge;

    hydra.getConsentRequest(challenge)
    // This will be called if the HTTP request was successful
        .then(function(response) {
            // If a user has granted this application the requested scope,
            // hydra will tell us to not show the UI.
            if (response.skip) {
                // You can apply logic here, for example grant
                // another scope, or do whatever...

                // Now it's time to grant the consent request. You could also
                // deny the request if something went terribly wrong
                return hydra.acceptConsentRequest(challenge, {
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
                        id_token: buildIDToken(
                            response.requested_scope, response.subject)
                    }
                }).then(function(response) {
                    // All we need to do now is to redirect the
                    // user back to hydra!
                    res.redirect(response.redirect_to);
                });
            }

            // If consent can't be skipped we MUST show the consent UI.
            res.render('consent', {
                baseUrl: baseUrl,
                csrfToken: req.csrfToken(),
                challenge: challenge,
                // We have a bunch of data available from the response,
                // check out the API docs to find what these values mean
                // and what additional data you have available.
                requested_scope: response.requested_scope,
                user: response.subject.replace('dcd:persons:',''),
                client: response.client,
            });
        })
        // This will handle any error that happens
        // when making HTTP calls to hydra
        .catch(function(error) {
            next(error);
        });
});

/**
 * Consent - Validation
 */
app.post(baseUrl + '/consent', csrfProtection, function(req, res, next) {
    // The challenge is now a hidden input field, so let's take it
    // from the request body instead
    const challenge = req.body.challenge;

    // Let's see if the user decided to accept or reject the consent request..
    if (req.body.submit === 'Deny access') {
        // Looks like the consent request was denied by the user
        return hydra.rejectConsentRequest(challenge, {
            error: 'access_denied',
            error_description: 'The resource owner denied the request'
        })
            .then(function(response) {
                // All we need to do now is to redirect
                // the browser back to hydra!
                res.redirect(response.redirect_to);
            })
            // This will handle any error that happens
            // when making HTTP calls to hydra
            .catch(function(error) {
                next(error);
            });
    }

    let grant_scope = req.body.grant_scope;
    if (!Array.isArray(grant_scope)) {
        grant_scope = [grant_scope];
    }
    // Seems like the user authenticated! Let's tell hydra...
    hydra.acceptConsentRequest(challenge, {
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
            id_token: buildIDToken(grant_scope, req.session.subject),

        },

        // This tells hydra to remember this consent request and allow the
        // same client to request the same
        // scopes from the same user, without showing the UI, in the future.
        remember: Boolean(req.body.remember),

        // When this "remember" sesion expires, in seconds. Set this to 0
        // so it will never expire.
        remember_for: 3600,
    })
        .then(function(response) {
            console.log('consent valid response:');
            console.log(response);
            // All we need to do now is to redirect the user back to hydra!
            res.redirect(response.redirect_to);
        })
        // This will handle any error that happens
        // when making HTTP calls to hydra
        .catch(function(error) {
            console.log('consent valid error:');
            console.log(error);
            next(error);
        });
});

function getPersonDetails(subject) {
    const url = process.env.API_URL + '/persons/' + subject;
    return auth.refresh().then(() => {
        return auth.authorisedRequest('GET', url);
    });
}

function buildIDToken(grant_scope, subject) {
    console.log('build id token: ' + subject);
    const username = subject.replace('dcd:persons:', '');
    const idToken = {};
    // This is the openid 'profile' scope which should include
    // some user profile data. (optional)
    if (grant_scope.indexOf('profile') >= 0) {
        idToken.id = username;
        idToken.sub = username;
        idToken.name = username;
        idToken.given_name = username;
        idToken.family_name = '';
        idToken.profile = '';
    }

    // This is to fulfill the openid 'email' scope which returns
    // the user's email address. (optional)
    if (grant_scope.indexOf('email') >= 0) {
        idToken.email = username;
        idToken.email_verified = false;
    }

    if (grant_scope.indexOf('phone') >= 0) {
        idToken.phone_number = '';
        idToken.phone_verified = false;
    }
}


/**
 * Sign in - Display
 */
app.get(baseUrl + '/signin', csrfProtection, function(req, res, next) {
    // Parses the URL query
    const query = url.parse(req.url, true).query;

    // The challenge is used to fetch information
    // about the login request from ORY Hydra.
    const challenge = query.login_challenge;

    hydra.getLoginRequest(challenge)
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
                return hydra.acceptLoginRequest(challenge, {
                    // All we need to do is to confirm that we indeed
                    // want to log in the user.
                    subject: response.subject
                }).then(function(response) {
                    // All we need to do now is to redirect the user
                    // back to hydra!
                    res.redirect(response.redirect_to);
                });
            }

            // If authentication can't be skipped
            // we MUST show the login UI.
            res.render('signin', {
                baseUrl: baseUrl,
                csrfToken: req.csrfToken(),
                challenge: challenge,
            });
        })
        // This will handle any error that happens
        // when making HTTP calls to hydra
        .catch(function(error) {
            next(error);
        });
});

/**
 * Sign in - Validation
 */
app.post(baseUrl + '/signin', csrfProtection, function(req, res, next) {
    // The challenge is now a hidden input field,
    // so let's take it from the request body instead
    const challenge = req.body.challenge;

    const url = process.env.API_URL + '/persons/'
        + req.body.email + '/check';
    const body = {
        password: req.body.password
    };
    auth.refresh().then(() => {
        auth.authorisedRequest('POST', url, body)
            .then((result) => {
                // Tell hydra to login this user
                console.log(result);
                if (result.person !== undefined && result.person.valid) {
                    req.subject = req.body.email;
                    login(req, res, next);
                } else {
                    // Looks like the user provided invalid credentials,
                    // let's show the ui again...
                    res.render('signin', {
                        baseUrl: baseUrl,
                        csrfToken: req.csrfToken(),
                        challenge: challenge,
                        error: 'The email / password combination is not correct'
                    });
                }
            }).catch((error) => {
            next(error);
        });
    });
});


/**
 * Sign up - Display
 */
app.get(baseUrl + '/signup', csrfProtection, function(req, res, next) {
    // Parses the URL query
    const query = url.parse(req.url, true).query;

    // The challenge is used to fetch information
    // about the login request from ORY Hydra.
    const challenge = query.login_challenge;

    hydra.getLoginRequest(challenge)
    // This will be called if the HTTP request was successful
        .then(function(response) {
            // If hydra was already able to authenticate the user,
            // skip will be true and we do not need to re-authenticate
            // the user.
            if (response.skip) {
                // Now it's time to grant the login request. You could also
                // deny the request if something went terribly wrong
                return hydra.acceptLoginRequest(challenge, {
                    // All we need to do is to confirm that we indeed
                    // want to log in the user.
                    subject: response.subject
                }).then(function(response) {
                    // All we need to do now is to redirect the user
                    // back to hydra!
                    res.redirect(response.redirect_to);
                });
            }

            // If authentication can't be skipped
            // we MUST show the sign up UI.
            res.render('signup', {
                baseUrl: baseUrl,
                csrfToken: req.csrfToken(),
                challenge: challenge,
            });
        })
        // This will handle any error that happens
        // when making HTTP calls to hydra
        .catch(function(error) {
            next(error);
        });
});

/**
 * Sign up - Validation
 */
app.post(baseUrl + '/signup', csrfProtection, function(req, res, next) {

    const url = process.env.API_URL + '/persons';
    const body = {
        id: req.body.email,
        name: req.body.name,
        password: req.body.password
    };
    auth.refresh().then(() => {
        auth.authorisedRequest('POST', url, body)
            .then((result) => {
                req.subject = result.personId;
                login(req, res, next);
            })
            .catch((error) => {
                res.render('signup', {
                    baseUrl: baseUrl,
                    csrfToken: req.csrfToken(),
                    challenge: req.body.challenge,
                    error: error.message
                });
            });
    }).catch((error) => {
        console.log(error);
        res.redirect(baseUrl + '/error');
    });
});

/**
 * Error
 */
app.get(baseUrl + '/error', csrfProtection, function(req, res, next) {
    res.send('error!');
});

function login(req, res, next) {
    // Seems like the user authenticated! Let's tell hydra...
    hydra.acceptLoginRequest(req.body.challenge, {
        // Subject is an alias for user ID. A subject can be a random string,
        // a UUID, an email address, ....
        subject: 'dcd:persons:' + req.subject,

        // This tells hydra to remember the browser and automatically
        // authenticate the user in future requests. This will
        // set the "skip" parameter in the other
        // route to true on subsequent requests!
        remember: Boolean(req.body.remember),

        // When the session expires, in seconds. Set this to 0
        // so it will never expire.
        remember_for: 3600,

        // Sets which "level" (e.g. 2-factor authentication) of
        // authentication the user has. The value is really arbitrary
        // and optional. In the context of OpenID Connect, a value
        // of 0 indicates the lowest authorization level.
        // acr: '0',
    })
        .then(function(response) {
            req.session.subject = req.subject;
            // All we need to do now is to redirect the
            // user back to hydra!
            res.redirect(response.redirect_to);
        })
        // This will handle any error that happens when making
        // HTTP calls to hydra
        .catch(function(error) {
            next(error);
        });

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

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    const err = new Error('Not Found');
    err.status = 404;
    next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res) {
        res.status(err.status || 500);
        res.render('error', {
            baseUrl: baseUrl,
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res) {
    res.status(err.status || 500);
    res.render('error', {
        baseUrl: baseUrl,
        message: err.message,
        error: {}
    });
});


module.exports = app;
