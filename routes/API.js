"use strict";

// Setting the logs
const log4js = require("log4js");

// Express router
const express = require("express");

class API {
  constructor(auth) {
    this.auth = auth;
    this.router = express.Router();

    this.logger = log4js.getLogger(
      "[dcd-app-identity-provider:" + this.constructor.name + "]"
    );
    this.logger.level = process.env.LOG_LEVEL || "INFO";

    // Sets up csrf protection
    const csrf = require("csurf");
    this.csrfProtection = csrf({ cookie: true });

    this.baseUrl = process.env.BASE_URL || "/auth";

    this.init();
  }

  init() {}
}

module.exports = API;
