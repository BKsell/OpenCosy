'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'contrastpref', prefix: 'CONTRASTP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateContrastprefGuard: guard.evaluate,
  summarizeContrastprefGuard: guard.summarize,
  describeContrastprefGuard: guard.describe,
};
