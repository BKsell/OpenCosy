'use strict'

// browsermimedirectoryguard.js —— 浏览器资源 MIME 活动内容分级目录。
//
// 威胁模型：
//   浏览器对 HTML/XML/SVG/PDF/multipart 等会主动渲染或嵌套脚本，图片/字体/音视频不活动。
//   纯字符查表，不用正则。

const MMD_CLASS = Object.freeze({ BLOCK: 'block', WARN: 'warn', ALLOW: 'allow', UNKNOWN: 'unknown' })

const MMD_BLOCK = Object.freeze([
  'text/html',
  'application/xhtml+xml',
  'application/xml',
  'text/xml',
  'image/svg+xml',
  'multipart/x-mixed-replace',
  'application/pdf',
  'text/javascript',
  'application/javascript',
  'application/ecmascript',
  'text/ecmascript',
  'application/x-javascript',
])

const MMD_WARN = Object.freeze([
  'text/css',
  'application/manifest+json',
  'application/x-web-app-manifest+json',
  'application/json-patch+json',
  'application/merge-patch+json',
  'multipart/form-data',
  'multipart/related',
  'multipart/alternative',
  'multipart/signed',
  'multipart/encrypted',
  'multipart/mixed',
  'application/zip',
  'application/x-zip-compressed',
  'application/x-rar-compressed',
  'application/x-7z-compressed',
  'application/x-tar',
  'application/gzip',
  'application/x-bzip2',
  'application/x-xz',
  'application/x-iso9660-image',
  'application/x-apple-diskimage',
  'application/wasm',
  'text/cache-manifest',
  'application/vnd.mozilla.xul+xml',
  'application/mac-binhex40',
  'application/octet-stream',
  'application/java-archive',
  'application/java-vm',
  'application/java-class',
  'application/x-java-jnlp-file',
  'application/java-serialized-object',
  'application/x-msdownload',
  'application/x-sh',
  'application/x-shellscript',
  'application/x-executable',
  'application/x-dosexec',
  'application/x-mach-binary',
  'text/vbscript',
  'application/hta',
  'application/x-silverlight-app',
  'application/x-shockwave-flash',
  'application/vnd.android.package-archive',
  'application/x-www-form-urlencoded',
  'application/atom+xml',
  'application/rss+xml',
  'application/soap+xml',
  'application/ld+json',
  'application/json',
  'text/csv-schema',
])

const MMD_ALLOW = Object.freeze([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/bmp',
  'image/webp',
  'image/avif',
  'image/jxl',
  'image/heic',
  'image/heif',
  'image/tiff',
  'image/x-icon',
  'image/vnd.microsoft.icon',
  'image/jp2',
  'image/jpx',
  'image/apng',
  'image/x-xbitmap',
  'image/x-xpixmap',
  'image/x-tga',
  'image/vnd.adobe.photoshop',
  'image/dicom-rle',
  'image/emf',
  'image/wmf',
  'audio/mpeg',
  'audio/mp3',
  'audio/wav',
  'audio/wave',
  'audio/x-wav',
  'audio/flac',
  'audio/aac',
  'audio/ogg',
  'audio/vorbis',
  'audio/opus',
  'audio/webm',
  'audio/mp4',
  'audio/m4a',
  'audio/x-m4a',
  'audio/aiff',
  'audio/midi',
  'audio/x-midi',
  'audio/x-ms-wma',
  'audio/basic',
  'audio/3gpp',
  'audio/ac3',
  'audio/amr',
  'video/mpeg',
  'video/mp4',
  'video/ogg',
  'video/webm',
  'video/x-msvideo',
  'video/avi',
  'video/x-ms-wmv',
  'video/quicktime',
  'video/x-matroska',
  'video/mp2t',
  'video/3gpp',
  'video/h264',
  'video/theora',
  'video/raw',
  'video/x-flv',
  'video/x-m4v',
  'font/ttf',
  'font/otf',
  'font/woff',
  'font/woff2',
  'font/collection',
  'font/sfnt',
  'application/font-sfnt',
  'application/x-font-ttf',
  'application/x-font-opentype',
  'application/vnd.ms-fontobject',
  'application/font-woff',
  'application/font-woff2',
  'text/plain',
  'text/markdown',
  'text/x-markdown',
  'text/tab-separated-values',
  'text/csv',
  'text/troff',
  'text/richtext',
  'text/uri-list',
  'text/yaml',
  'application/cbor',
  'application/msgpack',
  'application/x-protobuf',
  'application/x-ndjson',
  'application/x-yaml',
  'application/toml',
  'application/pgp-signature',
  'application/pgp-keys',
  'application/pgp-encrypted',
])

function MMDLower (x) {
  let out = ''
  for (let i = 0; i < x.length; i++) {
    const c = x.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : x[i]
  }
  return out
}

function MMDIn (list, v) {
  for (const x of list) { if (MMDLower(x) === v) return true }
  return false
}

function MMDClassify (tok) {
  const v = MMDLower(String(tok == null ? '' : tok).trim())
  if (MMDIn(MMD_BLOCK, v)) return MMD_CLASS.BLOCK
  if (MMDIn(MMD_WARN, v)) return MMD_CLASS.WARN
  if (MMDIn(MMD_ALLOW, v)) return MMD_CLASS.ALLOW
  return MMD_CLASS.UNKNOWN
}

module.exports = Object.freeze({
  MMD_CLASS: MMD_CLASS,
  MMD_BLOCK: MMD_BLOCK,
  MMD_WARN: MMD_WARN,
  MMD_ALLOW: MMD_ALLOW,
  MMDClassify: MMDClassify
})
