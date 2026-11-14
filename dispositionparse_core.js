'use strict';

function parseDisposition(value) {
  const text = String(value || '');
  const semi = text.indexOf(';');
  const type = (semi < 0 ? text : text.slice(0, semi)).trim().toLowerCase();
  if (!/^[a-z0-9-]+$/.test(type)) return null;
  let filename = null;
  const quoted = /filename\s*=\s*"([^"]*)"/i.exec(text);
  if (quoted) filename = quoted[1];
  if (filename === null) {
    const plain = /filename\s*=\s*([^;]+)/i.exec(text);
    if (plain) filename = plain[1].trim();
  }
  if (filename === null) {
    const star = /filename\*\s*=\s*[^']*''([^;]+)/i.exec(text);
    if (star) {
      try {
        filename = decodeURIComponent(star[1].trim());
      } catch {
        return null;
      }
    }
  }
  return { type, filename };
}

function headerValues(headers, name) {
  const target = name.toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() !== target) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.slice();
    if (typeof value === 'string') return [value];
  }
  return [];
}

function replaceHeader(headers, name, values) {
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === name.toLowerCase()) delete headers[key];
  }
  if (values.length) headers[name] = values;
}

function quoteFilename(name) {
  return `"${String(name).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

module.exports = { parseDisposition, headerValues, replaceHeader, quoteFilename };
