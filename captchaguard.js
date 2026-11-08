'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'captcha', prefix: 'CAPTCHA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCaptchaGuard: guard.evaluate,
  summarizeCaptchaGuard: guard.summarize,
  describeCaptchaGuard: guard.describe,
};
