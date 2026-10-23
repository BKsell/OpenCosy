'use strict'

// cloudmetadataguard.js —— 云元数据端点（169.254.169.254 等）出向访问守卫。
//
// 威胁模型：
//   浏览器内核/内置抓取若跟随页面或下载给出的 URL，可能被引导去请求云实例元数据服务，窃取临时
//   凭证（IMDSv1 无需令牌）：
//     - AWS/阿里云：http://169.254.169.254/latest/meta-data/iam/...
//     - GCP：http://metadata.google.internal/computeMetadata/v1/（要求 Metadata-Flavor 头）
//     - Azure：http://169.254.169.254/metadata/instance?api-version=...（要求 Metadata: true）
//   本模块审计目标主机/IP 与路径、以及是否携带云厂要求的元数据头（带了反而更可疑，说明在模拟
//   IMDSv2/GCP/Azure 调用）。地址识别复用 ipliteralguard。纯字符判定，不使用正则。

const { IpLiteralGuard } = require('./ipliteralguard.js')

const CM_REASON = Object.freeze({
  LINKLOCAL_METADATA_IP: 'target-is-link-local-metadata-address',
  METADATA_HOSTNAME: 'target-hostname-is-cloud-metadata-endpoint',
  METADATA_PATH: 'url-path-targets-instance-metadata',
  METADATA_SPOOF_HEADER: 'request-carries-cloud-metadata-spoof-header'
})

const METADATA_HOSTS = ['metadata.google.internal', 'metadata', '169.254.169.254', 'fd00:ec2::254']
const METADATA_HEADERS = ['metadata', 'metadata-flavor', 'x-aws-ec2-metadata-token']

function cmLower (s) {
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    out += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]
  }
  return out
}

class CloudMetadataGuard {
  constructor () {
    this.ip = new IpLiteralGuard()
  }

  // in: { host(去端口), path, headers:[{name,value}] }
  evaluate (input) {
    const inp = input || {}
    const findings = []
    const host = cmLower(String(inp.host || ''))

    for (const mh of METADATA_HOSTS) {
      if (host === mh || host === '[' + mh + ']') {
        findings.push({ reason: CM_REASON.METADATA_HOSTNAME, detail: host })
      }
    }
    if (this.ip.isInternal(inp.host)) {
      const norm = this.ip.normalize(inp.host)
      if (norm.class === 'linklocal') findings.push({ reason: CM_REASON.LINKLOCAL_METADATA_IP })
    }
    const path = cmLower(String(inp.path || ''))
    if (path.indexOf('/latest/meta-data') >= 0 ||
        path.indexOf('/metadata/instance') >= 0 ||
        path.indexOf('/computemetadata/') >= 0 ||
        path.indexOf('/metadata/') >= 0) {
      findings.push({ reason: CM_REASON.METADATA_PATH })
    }
    for (const h of inp.headers || []) {
      const n = cmLower(String(h.name))
      for (const mh of METADATA_HEADERS) {
        if (n === mh) findings.push({ reason: CM_REASON.METADATA_SPOOF_HEADER, detail: n })
      }
    }
    return { safe: findings.length === 0, findings: findings }
  }
}

module.exports = Object.freeze({
  CM_REASON: CM_REASON,
  METADATA_HOSTS: METADATA_HOSTS,
  CloudMetadataGuard: CloudMetadataGuard
})
