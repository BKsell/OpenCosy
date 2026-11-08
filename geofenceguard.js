'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'geofence', prefix: 'GEOFENCE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateGeofenceGuard: guard.evaluate,
  summarizeGeofenceGuard: guard.summarize,
  describeGeofenceGuard: guard.describe,
};
