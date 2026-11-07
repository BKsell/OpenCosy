'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'speech-empty',
  INSECURE: 'speech-insecure',
  NO_GRAMMAR: 'speech-no-grammar',
  REMOTE_GRAMMAR: 'speech-remote-grammar',
  TOO_LONG: 'speech-too-long',
};

const MAX_PHRASE = 256;
const MAX_PHRASES = 200;

function evaluateSpeechConfig(config, options) {
  const opts = options || {};
  const item = config || {};
  const origin = typeof item.origin === 'string' ? item.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  const phrases = Array.isArray(item.phrases) ? item.phrases : [];
  if (phrases.length === 0 && !Array.isArray(item.grammars)) {
    return { ok: false, blocked: true, reason: REASON.NO_GRAMMAR, origin };
  }
  if (phrases.length > MAX_PHRASES) {
    return { ok: false, blocked: true, reason: REASON.TOO_LONG, count: phrases.length };
  }
  for (const phrase of phrases) {
    const text = String(phrase || '');
    if (text.length > MAX_PHRASE) {
      return { ok: false, blocked: true, reason: REASON.TOO_LONG, size: text.length, limit: MAX_PHRASE };
    }
    if (/[\u0000-\u001f]/.test(text)) {
      return { ok: false, blocked: true, reason: REASON.EMPTY, sample: text.slice(0, 24) };
    }
  }
  const grammars = Array.isArray(item.grammars) ? item.grammars : [];
  for (const grammar of grammars) {
    const src = String((grammar && grammar.src) || '');
    if (src === '') continue;
    if (src.startsWith('http://')) {
      return { ok: false, blocked: true, reason: REASON.INSECURE, src: src.slice(0, 48) };
    }
    if (!src.startsWith('https://') && !src.startsWith('data:')) {
      return { ok: false, blocked: true, reason: REASON.REMOTE_GRAMMAR, src: src.slice(0, 48) };
    }
    if (!opts.allowRemoteGrammar && src.startsWith('https://')) {
      return { ok: false, blocked: false, reason: REASON.REMOTE_GRAMMAR, src: src.slice(0, 48) };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, phrases: phrases.length };
}

module.exports = {
  REASON,
  MAX_PHRASE,
  MAX_PHRASES,
  evaluateSpeechConfig,
};
