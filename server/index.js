'use strict';

const config = require('./config');
const register = require('./register');
const bootstrap = require('./bootstrap');
const contentTypes = require('./content-types');
const controllers = require('./controllers');
const routes = require('./routes');
const services = require('./services');

module.exports = {
  register,
  bootstrap,
  config,
  contentTypes,
  controllers,
  routes,
  services,
};
