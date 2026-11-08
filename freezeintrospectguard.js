'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'freezeintrospect', prefix: 'FREEZEINT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFreezeintrospectGuard: guard.evaluate,
  summarizeFreezeintrospectGuard: guard.summarize,
  describeFreezeintrospectGuard: guard.describe,
};
