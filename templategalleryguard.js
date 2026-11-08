'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'templategallery', prefix: 'TEMPLATEG' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateTemplategalleryGuard: guard.evaluate,
  summarizeTemplategalleryGuard: guard.summarize,
  describeTemplategalleryGuard: guard.describe,
};
