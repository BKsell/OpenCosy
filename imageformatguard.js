'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'imageformat', prefix: 'IMAGEFORM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateImageformatGuard: guard.evaluate,
  summarizeImageformatGuard: guard.summarize,
  describeImageformatGuard: guard.describe,
};
