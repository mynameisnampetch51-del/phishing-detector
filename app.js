const HISTORY_KEY = 'phishing-history';
const MAX_HISTORY = 10;
const ML_API_URL = 'http://localhost:8000/predict';

const LEVEL_META = {
  safe: { label: 'ปลอดภัย', bg: 'bg-good-soft', text: 'text-good-ink', ring: 'ring-good' },
  suspicious: { label: 'น่าสงสัย', bg: 'bg-warn-soft', text: 'text-warn-ink', ring: 'ring-warn' },
  dangerous: { label: 'อันตรายสูง', bg: 'bg-accent-soft', text: 'text-accent-strong', ring: 'ring-accent' },
};

const input = document.querySelector('#UrlInput');
const button = document.querySelector('#CheckButton');
const errorMsg = document.querySelector('#ErrorMsg');
const resultEl = document.querySelector('#Result');
const historyEl = document.querySelector('#History');
const mlResultEl = document.querySelector('#MLResult');

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

function renderResult(evaluation) {
  if (!evaluation.valid) {
    errorMsg.textContent = evaluation.error;
    errorMsg.classList.remove('hidden');
    resultEl.innerHTML = '';
    return;
  }
  errorMsg.classList.add('hidden');

  const meta = LEVEL_META[evaluation.level];
  const triggeredCount = evaluation.results.filter((r) => r.triggered).length;

  const card = document.createElement('div');
  card.className = `bg-surface border border-line rounded-2xl shadow-sm p-5 ring-1 ${meta.ring}`;

  const header = document.createElement('div');
  header.className = 'flex items-center justify-between mb-4 gap-3';
  header.innerHTML = `
    <div>
      <span class="inline-block px-3 py-1 rounded-full text-sm font-semibold ${meta.bg} ${meta.text}">${meta.label}</span>
      <p class="text-sm text-ink-muted mt-2 break-words">${evaluation.hostname}</p>
    </div>
    <div class="text-right shrink-0">
      <div class="text-2xl font-display font-semibold">${evaluation.score}</div>
      <div class="text-xs text-ink-muted">คะแนนความเสี่ยง</div>
    </div>
  `;
  card.appendChild(header);

  const list = document.createElement('ul');
  list.className = 'flex flex-col gap-2';
  evaluation.results.forEach((r) => {
    const li = document.createElement('li');
    li.className = `flex gap-2 text-sm px-3 py-2 rounded-lg ${r.triggered ? 'bg-accent-soft' : 'bg-surface-2'}`;
    li.innerHTML = `
      <span class="${r.triggered ? 'text-accent-strong' : 'text-good'} font-bold shrink-0">${r.triggered ? '✕' : '✓'}</span>
      <span>
        <span class="font-medium">${r.label}</span>
        <span class="block text-ink-muted">${r.detail}</span>
      </span>
    `;
    list.appendChild(li);
  });
  card.appendChild(list);

  resultEl.innerHTML = '';
  resultEl.appendChild(card);

  console.log(`ตรวจ ${triggeredCount}/${evaluation.results.length} ข้อ เข้าเกณฑ์ — คะแนนรวม ${evaluation.score}`);
}

function renderHistory() {
  const list = loadHistory();
  historyEl.innerHTML = '';

  if (list.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'text-sm text-ink-muted';
    empty.textContent = 'ยังไม่มีประวัติการตรวจสอบ';
    historyEl.appendChild(empty);
    return;
  }

  list.forEach((entry) => {
    const meta = LEVEL_META[entry.level];
    const li = document.createElement('li');
    li.className = 'flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-line bg-surface-2 cursor-pointer text-sm';
    li.innerHTML = `
      <span class="truncate">${entry.url}</span>
      <span class="px-2 py-0.5 rounded-full font-medium shrink-0 ${meta.bg} ${meta.text}">${meta.label}</span>
    `;
    li.addEventListener('click', () => {
      input.value = entry.url;
      runCheck();
    });
    historyEl.appendChild(li);
  });
}

function renderMLPending() {
  mlResultEl.innerHTML = `
    <div class="text-sm text-ink-muted px-3 py-2">กำลังตรวจด้วยโมเดล ML...</div>
  `;
}

function renderMLResult(isPhishing) {
  const bg = isPhishing ? 'bg-accent-soft' : 'bg-good-soft';
  const text = isPhishing ? 'text-accent-strong' : 'text-good-ink';
  const label = isPhishing ? 'โมเดล ML: น่าจะเป็น Phishing' : 'โมเดล ML: น่าจะปลอดภัย';
  mlResultEl.innerHTML = `
    <div class="text-sm px-3 py-2 rounded-lg ${bg} ${text} font-medium">${label}</div>
  `;
}

function renderMLUnavailable() {
  mlResultEl.innerHTML = `
    <div class="text-sm text-ink-muted px-3 py-2">
      ตรวจด้วย ML ไม่ได้ — เปิด API ไว้ที่ localhost:8000 ก่อน (ดู phishing-detector/api/README.md)
    </div>
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
