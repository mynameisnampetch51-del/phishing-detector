const HISTORY_KEY = 'phishing-history';
const MAX_HISTORY = 10;
const ML_API_URL = 'http://localhost:8000/predict';

const LEVEL_LABELS = { safe: 'ปลอดภัย', suspicious: 'น่าสงสัย', dangerous: 'อันตรายสูง' };

const GAUGE_CX = 120;
const GAUGE_CY = 145;
const GAUGE_R = 95;
const GAUGE_HALF_SWEEP = 120;
const NS = 'http://www.w3.org/2000/svg';

const input = document.querySelector('#UrlInput');
const button = document.querySelector('#CheckButton');
const errorMsg = document.querySelector('#ErrorMsg');
const gaugeSection = document.querySelector('#GaugeSection');
const gaugeSvg = document.querySelector('#Gauge');
const scoreValueEl = document.querySelector('#ScoreValue');
const levelLabelEl = document.querySelector('#LevelLabel');
const hostnameLabelEl = document.querySelector('#HostnameLabel');
const checklistEl = document.querySelector('#Checklist');
const mlResultEl = document.querySelector('#MLResult');
const historyEl = document.querySelector('#History');

function loadHistory() {
  const raw = localStorage.getItem(HISTORY_KEY);
  return raw ? JSON.parse(raw) : [];
}

function saveHistory(list) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
}

function addToHistory(evaluation) {
  const list = loadHistory();
  list.unshift({ url: evaluation.url, level: evaluation.level, score: evaluation.score });
  saveHistory(list.slice(0, MAX_HISTORY));
  renderHistory();
}

// --- Gauge (same needle/arc approach as password-strength-checker/app.js) ---

function scoreToAngle(score) {
  const clamped = Math.max(0, Math.min(MAX_SCORE, score));
  return -GAUGE_HALF_SWEEP + (clamped / MAX_SCORE) * (GAUGE_HALF_SWEEP * 2);
}

function polarToCartesian(cx, cy, r, angleDeg) {
  const rad = (angleDeg * Math.PI) / 180;
  return { x: cx + r * Math.sin(rad), y: cy - r * Math.cos(rad) };
}

function arcPath(cx, cy, r, startAngle, endAngle) {
  const start = polarToCartesian(cx, cy, r, startAngle);
  const end = polarToCartesian(cx, cy, r, endAngle);
  const largeArc = endAngle - startAngle > 180 ? 1 : 0;
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`;
}

function svgEl(tag, attrs) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

function buildGauge() {
  const zones = [
    { from: 0, to: SCORE_THRESHOLDS.suspicious, color: 'var(--safe)' },
    { from: SCORE_THRESHOLDS.suspicious, to: SCORE_THRESHOLDS.dangerous, color: 'var(--warn)' },
    { from: SCORE_THRESHOLDS.dangerous, to: MAX_SCORE, color: 'var(--danger)' },
  ];
  zones.forEach((z) => {
    gaugeSvg.appendChild(svgEl('path', {
      class: 'zone',
      d: arcPath(GAUGE_CX, GAUGE_CY, GAUGE_R, scoreToAngle(z.from), scoreToAngle(z.to)),
      stroke: z.color,
      'stroke-width': 14,
    }));
  });

  for (let score = 0; score <= MAX_SCORE; score++) {
    const isMajor = score % 5 === 0;
    const angle = scoreToAngle(score);
    const outer = polarToCartesian(GAUGE_CX, GAUGE_CY, GAUGE_R - 9, angle);
    const inner = polarToCartesian(GAUGE_CX, GAUGE_CY, GAUGE_R - (isMajor ? 20 : 15), angle);
    gaugeSvg.appendChild(svgEl('line', {
      class: 'tick', x1: outer.x, y1: outer.y, x2: inner.x, y2: inner.y,
      'stroke-width': isMajor ? 2 : 1,
    }));
    if (isMajor) {
      const labelPos = polarToCartesian(GAUGE_CX, GAUGE_CY, GAUGE_R - 32, angle);
      const label = svgEl('text', { class: 'tick-label', x: labelPos.x, y: labelPos.y + 4 });
      label.textContent = score;
      gaugeSvg.appendChild(label);
    }
  }

  const needle = svgEl('g', { class: 'needle', style: `transform-origin:${GAUGE_CX}px ${GAUGE_CY}px` });
  needle.appendChild(svgEl('line', { x1: GAUGE_CX, y1: GAUGE_CY, x2: GAUGE_CX, y2: GAUGE_CY - 76 }));
  needle.appendChild(svgEl('circle', { cx: GAUGE_CX, cy: GAUGE_CY, r: 7 }));
  gaugeSvg.appendChild(needle);
  return needle;
}

const needleEl = buildGauge();

function setNeedle(score) {
  needleEl.style.transform = `rotate(${scoreToAngle(score)}deg)`;
}

// --- Rendering ---

function renderChecklist(results) {
  checklistEl.innerHTML = '';
  results.forEach((r) => {
    const li = document.createElement('li');
    li.className = r.triggered ? 'hit' : '';
    li.innerHTML = `
      <span class="mark">${r.triggered ? '✕' : '✓'}</span>
      <span>
        <span class="rule-label">${r.label}</span>
        <span class="rule-detail">${r.detail}</span>
      </span>
    `;
    checklistEl.appendChild(li);
  });
}

function renderResult(evaluation) {
  if (!evaluation.valid) {
    errorMsg.textContent = evaluation.error;
    errorMsg.style.display = 'block';
    gaugeSection.style.display = 'none';
    return;
  }
  errorMsg.style.display = 'none';
  gaugeSection.style.display = 'block';

  setNeedle(evaluation.score);
  scoreValueEl.textContent = evaluation.score;
  levelLabelEl.textContent = LEVEL_LABELS[evaluation.level];
  levelLabelEl.className = `level level--${evaluation.level}`;
  hostnameLabelEl.textContent = evaluation.hostname;

  renderChecklist(evaluation.results);
}

function renderHistory() {
  const list = loadHistory();
  historyEl.innerHTML = '';

  if (list.length === 0) {
    const empty = document.createElement('li');
    empty.style.cursor = 'default';
    empty.innerHTML = '<span class="empty-note">ยังไม่มีประวัติการตรวจสอบ</span>';
    historyEl.appendChild(empty);
    return;
  }

  list.forEach((entry) => {
    const li = document.createElement('li');
    li.innerHTML = `
      <span class="url">${entry.url}</span>
      <span class="badge badge--${entry.level}">${LEVEL_LABELS[entry.level]}</span>
    `;
    li.addEventListener('click', () => {
      input.value = entry.url;
      runCheck();
    });
    historyEl.appendChild(li);
  });
}

function renderMLPending() {
  mlResultEl.innerHTML = `<div class="ml-box pending">กำลังตรวจด้วยโมเดล ML...</div>`;
}

function renderMLResult(isPhishing) {
  const cls = isPhishing ? 'phishing' : 'legit';
  const label = isPhishing ? 'โมเดล ML: น่าจะเป็น Phishing' : 'โมเดล ML: น่าจะปลอดภัย';
  mlResultEl.innerHTML = `<div class="ml-box ${cls}">${label}</div>`;
}

function renderMLUnavailable() {
  mlResultEl.innerHTML = `
    <div class="ml-box unavailable">ตรวจด้วย ML ไม่ได้ — เปิด API ไว้ที่ localhost:8000 ก่อน (ดู phishing-detector/api/README.md)</div>
  `;
}

async function checkML(url) {
  renderMLPending();
  try {
    const res = await fetch(ML_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error('bad response');
    const data = await res.json();
    renderMLResult(data.isPhishing);
  } catch (err) {
    renderMLUnavailable();
  }
}

function runCheck() {
  const raw = input.value.trim();
  if (!raw) return;
  const evaluation = evaluateUrl(raw);
  renderResult(evaluation);
  if (evaluation.valid) {
    addToHistory(evaluation);
    checkML(raw);
  } else {
    mlResultEl.innerHTML = '';
  }
}

button.addEventListener('click', runCheck);
input.addEventListener('keypress', function (event) {
  if (event.key === 'Enter') runCheck();
});

renderHistory();
