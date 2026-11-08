'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'geolocation', prefix: 'GEOLOCATI' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGeolocationGuard: guard.evaluate,
  summarizeGeolocationGuard: guard.summarize,
  describeGeolocationGuard: guard.describe,
};
