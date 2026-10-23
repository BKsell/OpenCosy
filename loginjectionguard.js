'use strict'

// loginjectionguard.js —— 写入日志的外部可控值净化（日志伪造 / CRLF 注入）。
//
// 威胁模型：
//   浏览器会把网址、标题、下载文件名、扩展/页面回显的错误串写进本地日志（可能随"反馈"上传）。
//   若值里含 CR/LF，攻击者可伪造整行 "[INFO] 安全校验通过"，污染审计；ANSI 转义可在终端里移动
//   光标、清屏、篡改已打印内容；NUL/其它 C0 控制字符破坏行式解析。
//   本模块：检测 CR/LF/NUL/C0/ANSI 转义，并提供 sanitizeLog 产出可安全单行写入的文本。
//   纯字符处理，不使用正则。

const LI_REASON = Object.freeze({
  CRLF: 'log-value-contains-crlf-line-break',
  NUL: 'log-value-contains-nul-byte',
  ANSI: 'log-value-contains-ansi-escape',
  CONTROL: 'log-value-contains-c0-control-character'
})

function liAudit (value) {
  const s = String(value)
  const findings = []
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code === 13 || code === 10) {
      findings.push({ reason: LI_REASON.CRLF, index: i })
    } else if (code === 0) {
      findings.push({ reason: LI_REASON.NUL, index: i })
    } else if (code === 0x1B) {
      findings.push({ reason: LI_REASON.ANSI, index: i })
    } else if (code < 0x20 || code === 0x7F) {
      findings.push({ reason: LI_REASON.CONTROL, index: i })
    }
  }
  return { safe: findings.length === 0, findings: findings }
}

// CR/LF/NUL/C0 替换为 '_'，并消费整个 ANSI CSI 转义序列（ESC [ ... 终止字节），
// DEL(0x7f) 直接删除，保证输出是可重审的单行纯文本。
function sanitizeLog (value) {
  const s = String(value)
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i)
    if (code === 0x7F) continue
    if (code === 0x1B) {
      if (s[i + 1] === '[') {
        i += 2
        while (i < s.length) {
          const c = s.charCodeAt(i)
          if (c >= 0x40 && c <= 0x7E) break
          i++
        }
      }
      out += '_'
      continue
    }
    if (code === 13 || code === 10 || code < 0x20) {
      out += '_'
      continue
    }
    out += s[i]
  }
  return out
}

function liHasReason (findings, reason) {
  return findings.some((f) => f.reason === reason)
}

class LogInjectionGuard {
  evaluate (value) {
    return liAudit(value)
  }

  sanitize (value) {
    return sanitizeLog(value)
  }
}

module.exports = Object.freeze({
  LI_REASON: LI_REASON,
  sanitizeLog: sanitizeLog,
  liHasReason: liHasReason,
  LogInjectionGuard: LogInjectionGuard
})
