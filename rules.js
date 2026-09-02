const KNOWN_DOMAINS = [
  'google.com', 'facebook.com', 'paypal.com', 'apple.com', 'microsoft.com',
  'amazon.com', 'instagram.com', 'netflix.com', 'line.me', 'kbank.co.th',
  'scb.co.th', 'krungsri.com', 'truemoney.com', 'shopee.co.th', 'lazada.co.th',
];

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'tiny.cc',
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'account', 'confirm', 'banking', 'signin', 'password', 'wallet',
];


function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,      
        dp[i][j - 1] + 1,      
        dp[i - 1][j - 1] + cost 
      );
    }
  }
  return dp[m][n];
}

function checkIpHost(url) {
  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(url.hostname);
  return {
    id: 'ip-host',
    label: 'ใช้ IP แทนชื่อโดเมน',
    weight: 3,
    triggered: isIPv4,
    detail: isIPv4
      ? `hostname เป็นเลข IP (${url.hostname}) — เว็บที่น่าเชื่อถือแทบไม่ใช้ IP ตรงๆ ในแถบที่อยู่`
      : 'hostname เป็นชื่อโดเมนปกติ',
  };
}

function checkAtSymbol(rawInput) {
  const triggered = rawInput.includes('@');
  return {
    id: 'at-symbol',
    label: 'มีเครื่องหมาย @ ใน URL',
    weight: 3,
    triggered,
    detail: triggered
      ? 'เบราว์เซอร์จะมองทุกอย่างก่อน @ เป็นแค่ข้อมูล login แล้วพาไปโดเมนหลัง @ จริงๆ — เทคนิคหลอกลวงคลาสสิก'
      : 'ไม่พบเครื่องหมาย @',
  };
}

function checkHttps(url) {
  const triggered = url.protocol !== 'https:';
  return {
    id: 'https',
    label: 'ไม่ใช้ HTTPS',
    weight: 2,
    triggered,
    detail: triggered
      ? `โปรโตคอลคือ ${url.protocol.replace(':', '')} — ข้อมูลที่ส่งไม่ถูกเข้ารหัส`
      : 'ใช้ HTTPS แล้ว',
  };
}

function checkSubdomains(url) {
  const dotCount = (url.hostname.match(/\./g) || []).length;
  const triggered = dotCount >= 3;
  return {
    id: 'subdomains',
    label: 'มี subdomain ซ้อนเยอะผิดปกติ',
    weight: 1,
    triggered,
    detail: triggered
      ? `hostname มีจุดคั่น ${dotCount} จุด (${url.hostname}) — มักถูกใช้ซ่อนโดเมนจริงไว้ท้ายสุด`
      : 'จำนวน subdomain อยู่ในเกณฑ์ปกติ',
  };
}

function checkSuspiciousKeywords(url) {
  const target = (url.hostname + url.pathname).toLowerCase();
  const found = SUSPICIOUS_KEYWORDS.filter((k) => target.includes(k));
  const triggered = found.length > 0;
  return {
    id: 'keywords',
    label: 'มีคำที่มักถูกใช้หลอกลวง',
    weight: 1,
    triggered,
    detail: triggered
      ? `พบคำ: ${found.join(', ')} — มักถูกใช้ในหน้าฟิชชิ่งเพื่อสร้างความเร่งด่วน/น่าเชื่อถือปลอม`
      : 'ไม่พบคำต้องสงสัย',
  };
}

function checkLength(rawInput) {
  const triggered = rawInput.length > 75;
  return {
    id: 'length',
    label: 'URL ยาวผิดปกติ',
    weight: 1,
    triggered,
    detail: triggered
      ? `ยาว ${rawInput.length} ตัวอักษร — URL ที่ยาวมากมักใช้ซ่อน token หรือทำให้ดูซับซ้อนเกินจะตรวจสอบ`
      : `ยาว ${rawInput.length} ตัวอักษร อยู่ในเกณฑ์ปกติ`,
  };
}

function checkShortener(url) {
  const triggered = URL_SHORTENERS.some((s) => url.hostname === s || url.hostname.endsWith('.' + s));
  return {
    id: 'shortener',
    label: 'ใช้บริการย่อลิงก์',
    weight: 1,
    triggered,
    detail: triggered
      ? 'ลิงก์ย่อซ่อนปลายทางจริง ตรวจสอบตรงๆ ไม่ได้ — ไม่ได้แปลว่าอันตรายเสมอไป แต่ควรระวังเพิ่ม'
      : 'ไม่ได้ใช้บริการย่อลิงก์ที่รู้จัก',
  };
}

// สร้างรายชื่อ "ส่วนโดเมน" ที่เป็นไปได้จาก hostname เช่น accounts.g00gle.com
// -> ['accounts.g00gle.com', 'g00gle.com'] เพื่อจับ typosquat ที่ซ่อนอยู่หลัง subdomain ด้วย
function getDomainCandidates(hostname) {
  const labels = hostname.replace(/^www\./, '').split('.');
  const candidates = [];
  for (let i = 0; i < labels.length - 1; i++) {
    candidates.push(labels.slice(i).join('.'));
  }
  return candidates.length > 0 ? candidates : [hostname];
}

function checkTyposquatting(url) {
  const candidates = getDomainCandidates(url.hostname);
  let minDistance = Infinity;
  let matchedKnown = null;
  let matchedCandidate = null;

  outer:
  for (const candidate of candidates) {
    for (const domain of KNOWN_DOMAINS) {
      const distance = candidate === domain ? 0 : levenshtein(candidate, domain);
      if (distance < minDistance) {
        minDistance = distance;
        matchedKnown = domain;
        matchedCandidate = candidate;
      }
      if (minDistance === 0) break outer;
    }
  }

  const triggered = minDistance > 0 && minDistance <= 2;
  return {
    id: 'typosquat',
    label: 'คล้ายโดเมนดังผิดปกติ (typosquatting)',
    weight: 3,
    triggered,
    detail: triggered
      ? `ส่วนโดเมน "${matchedCandidate}" ต่างจาก "${matchedKnown}" แค่ ${minDistance} ตัวอักษร — อาจตั้งใจเลียนแบบ`
      : 'ไม่คล้ายโดเมนดังในรายการที่เช็ค',
  };
}

// รันทุกกฎกับ URL ที่ผู้ใช้กรอก แล้วสรุปคะแนน + ระดับความเสี่ยง
function evaluateUrl(rawInput) {
  let url;
  try {
    url = new URL(rawInput);
  } catch (e) {
    return { valid: false, error: 'รูปแบบ URL ไม่ถูกต้อง (ต้องมี http:// หรือ https:// นำหน้า)' };
  }

  const results = [
    checkIpHost(url),
    checkAtSymbol(rawInput),
    checkHttps(url),
    checkSubdomains(url),
    checkSuspiciousKeywords(url),
    checkLength(rawInput),
    checkShortener(url),
    checkTyposquatting(url),
  ];

  const score = results.reduce((sum, r) => sum + (r.triggered ? r.weight : 0), 0);

  let level;
  if (score === 0) level = 'safe';
  else if (score <= 3) level = 'suspicious';
  else level = 'dangerous';

  return { valid: true, url: rawInput, hostname: url.hostname, results, score, level };
}
