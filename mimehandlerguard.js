'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'mimehandler', prefix: 'MIMEHANDL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateMimehandlerGuard: guard.evaluate,
  summarizeMimehandlerGuard: guard.summarize,
  describeMimehandlerGuard: guard.describe,
};
