const form = document.getElementById('scan-form');
const input = document.getElementById('url-input');
const message = document.getElementById('message');
const resultCard = document.getElementById('result-card');
const historyList = document.getElementById('history-list');
const historyKey = 'aegis-url-history-v2';
try { localStorage.removeItem('aegis-url-history-v1'); } catch {}
let sequence = 0;
let scrollAnimation;
let scrollResolve;
let previousScrollBehavior;
let visualObserver;
let scoreAnimation;

const featureGroups = {
  structure: new Set(['http', 'ip_host', 'subdomains', 'long', 'very_long', 'port']),
  disguise: new Set(['userinfo', 'idn', 'mixed_script', 'hyphens', 'shortener']),
  intent: new Set(['lure_word', 'lure_words', 'download', 'redirect'])
};

function formatCount(number) { return new Intl.NumberFormat('ru-RU').format(number); }

function formatFeedDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat('ru-RU', {day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Europe/Moscow'}).format(date);
}

async function loadFeedStatus() {
  try {
    const response = await fetch('/api/status');
    const data = await response.json();
    if (data.database?.loaded) document.getElementById('hero-feed-count').textContent = formatCount(data.database.count);
    else document.getElementById('hero-feed-count').textContent = '0';
  } catch { document.getElementById('hero-feed-count').textContent = '—'; }
}

function showDatabase(result) {
  const database = result.database || {loaded: false, count: 0};
  document.getElementById('database-count').textContent = database.loaded ? formatCount(database.count) : '—';
  document.getElementById('database-date').textContent = database.loaded ? formatFeedDate(database.updated_at) : 'Не загружена';
  const status = document.getElementById('database-result');
  status.className = `database-result ${result.database_match ? 'matched' : database.loaded ? 'checked' : 'unavailable'}`;
  status.textContent = result.database_match ? 'Точное совпадение найдено' : database.loaded ? 'Точного совпадения не найдено' : 'База ещё не загружена';
}

function showFeatureChart(indicators) {
  const totals = {structure: 0, disguise: 0, intent: 0};
  for (const item of indicators) {
    for (const [group, codes] of Object.entries(featureGroups)) {
      if (codes.has(item.code)) totals[group] += item.points;
    }
  }
  const max = Math.max(20, ...Object.values(totals));
  for (const [group, value] of Object.entries(totals)) {
    document.getElementById(`value-${group}`).textContent = value;
    document.getElementById(`bar-${group}`).style.width = '0%';
  }
  return {totals, max};
}

function revealReport() {
  stopScroll();
  const target = Math.max(0, resultCard.getBoundingClientRect().top + window.scrollY - 18);
  previousScrollBehavior = document.documentElement.style.scrollBehavior;
  document.documentElement.style.scrollBehavior = 'auto';
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    window.scrollTo(0, target);
    document.documentElement.style.scrollBehavior = previousScrollBehavior;
    return Promise.resolve();
  }
  return new Promise(resolve => {
    scrollResolve = () => { document.documentElement.style.scrollBehavior = previousScrollBehavior; scrollResolve = null; resolve(); };
    const from = window.scrollY;
    const started = performance.now();
    const duration = 780;
    function frame(now) {
      const t = Math.min(1, (now - started) / duration);
      const eased = 1 - (1 - t) ** 3;
      window.scrollTo(0, from + (target - from) * eased);
      if (t < 1) scrollAnimation = requestAnimationFrame(frame);
      else scrollResolve();
    }
    scrollAnimation = requestAnimationFrame(frame);
  });
}

function stopScroll() {
  cancelAnimationFrame(scrollAnimation);
  scrollResolve?.();
}

function resetVisuals() {
  visualObserver?.disconnect();
  cancelAnimationFrame(scoreAnimation);
  const ring = document.getElementById('score-ring');
  ring.style.transition = 'none';
  ring.style.setProperty('--score', 0);
  document.getElementById('score-number').textContent = '0';
  const bars = [];
  for (const group of Object.keys(featureGroups)) {
    const bar = document.getElementById(`bar-${group}`);
    bar.style.transition = 'none';
    bar.style.width = '0%';
    bars.push(bar);
    document.getElementById(`value-${group}`).textContent = '0';
  }
  void ring.offsetWidth;
  ring.style.removeProperty('transition');
  for (const bar of bars) { void bar.offsetWidth; bar.style.removeProperty('transition'); }
}

function prepareReport() {
  resetVisuals();
  resultCard.hidden = false;
  resultCard.dataset.level = 'pending';
  resultCard.classList.remove('report-animate');
  resultCard.classList.add('is-pending');
  document.getElementById('verdict-title').textContent = 'Проверяем адрес';
  document.getElementById('verdict-summary').textContent = '';
  document.getElementById('result-host').textContent = '';
  document.getElementById('database-result').textContent = 'Сверяем с базой…';
  document.getElementById('findings').replaceChildren();
}

function animateVisuals(score, chart) {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const ring = document.getElementById('score-ring');
  const number = document.getElementById('score-number');
  const bars = document.querySelector('.chart-panel');
  function drawScore() {
    ring.style.setProperty('--score', score);
    if (reduced) { number.textContent = score; return; }
    const started = performance.now();
    function frame(now) {
      const t = Math.min(1, (now - started) / 1050);
      number.textContent = Math.round(score * (1 - (1 - t) ** 3));
      if (t < 1) scoreAnimation = requestAnimationFrame(frame);
    }
    scoreAnimation = requestAnimationFrame(frame);
  }
  function drawBars() {
    for (const [group, value] of Object.entries(chart.totals)) {
      document.getElementById(`bar-${group}`).style.width = `${Math.round(value / chart.max * 100)}%`;
    }
  }
  if (reduced || !('IntersectionObserver' in window)) { drawScore(); drawBars(); return; }
  visualObserver = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      if (entry.target === ring) drawScore();
      if (entry.target === bars) drawBars();
      visualObserver.unobserve(entry.target);
    }
  }, {threshold: .2});
  visualObserver.observe(ring);
  visualObserver.observe(bars);
}

function setMessage(text) {
  message.textContent = text;
  message.hidden = !text;
}

function getHistory() {
  try {
    const items = JSON.parse(localStorage.getItem(historyKey) || '[]');
    return Array.isArray(items) ? items.filter(item => typeof item.host === 'string' && (item.host.includes('.') || item.host === 'localhost')) : [];
  }
  catch { return []; }
}

function saveHistory(result) {
  try {
    const items = getHistory().filter(item => item.host !== result.host);
    items.unshift({host: result.host, score: result.score, level: result.level, label: result.label, at: Date.now()});
    localStorage.setItem(historyKey, JSON.stringify(items.slice(0, 6)));
  } catch { /* Private browsing may disable storage. Analysis still works. */ }
  renderHistory();
}

function renderHistory() {
  const items = getHistory();
  historyList.replaceChildren();
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-history';
    empty.textContent = 'Проверок пока нет.';
    historyList.append(empty);
    return;
  }
  for (const item of items) {
    const button = document.createElement('div');
    button.className = 'history-item';
    const dot = document.createElement('span');
    dot.className = `history-dot ${item.level}`;
    const text = document.createElement('span');
    text.className = 'history-text';
    const host = document.createElement('strong');
    host.textContent = item.host;
    button.setAttribute('aria-label', `${item.host}: ${item.label}, ${item.score} из 100`);
    text.append(host);
    const score = document.createElement('b');
    score.textContent = item.score;
    button.append(dot, text, score);
    historyList.append(button);
  }
}

function renderResult(result) {
  resultCard.hidden = false;
  resultCard.dataset.level = result.level;
  resultCard.classList.remove('is-pending');
  resultCard.classList.remove('report-animate');
  void resultCard.offsetWidth;
  resultCard.classList.add('report-animate');
  resetVisuals();
  document.getElementById('verdict-title').textContent = result.label;
  document.getElementById('verdict-summary').textContent = result.summary;
  document.getElementById('result-host').textContent = result.host;
  showDatabase(result);
  const chart = showFeatureChart(result.indicators);
  const list = document.getElementById('findings');
  list.replaceChildren();
  if (!result.indicators.length) {
    const empty = document.createElement('p');
    empty.className = 'no-findings';
    empty.textContent = 'Заметных признаков не найдено.';
    list.append(empty);
  } else {
    for (const [index, item] of result.indicators.entries()) {
      const row = document.createElement('details');
      row.className = 'finding';
      const summary = document.createElement('summary');
      const mark = document.createElement('span');
      mark.className = 'finding-mark';
      mark.textContent = String(index + 1).padStart(2, '0');
      const title = document.createElement('strong');
      title.textContent = item.title;
      const detail = document.createElement('p');
      detail.textContent = item.detail;
      const points = document.createElement('span');
      points.className = 'finding-points';
      points.textContent = `+${item.points}`;
      summary.append(mark, title, points);
      row.append(summary, detail);
      list.append(row);
    }
  }
  requestAnimationFrame(() => animateVisuals(result.score, chart));
}

async function analyze(reveal = false) {
  const url = input.value.trim();
  const current = ++sequence;
  if (!url) { resultCard.hidden = true; setMessage(''); return; }
  const candidate = url.replace(/^https?:\/\//i, '').split(/[/?#]/, 1)[0];
  if (reveal && !candidate.includes('.') && candidate !== 'localhost') {
    resultCard.hidden = true;
    setMessage('Укажите полный домен, например example.com.');
    return;
  }
  setMessage('');
  form.classList.add('loading');
  const scrollTask = reveal ? (prepareReport(), revealReport()) : null;
  try {
    const response = await fetch('/api/analyze', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url})});
    const data = await response.json();
    if (current !== sequence) return;
    if (!response.ok) {
      if (reveal) stopScroll();
      resultCard.hidden = true;
      setMessage(data.error || 'Не удалось проверить адрес.');
      return;
    }
    if (scrollTask) await scrollTask;
    if (current !== sequence) return;
    renderResult(data);
    saveHistory(data);
  } catch {
    if (current === sequence) { resultCard.hidden = true; setMessage('Нет соединения с локальным сервером. Проверьте, что окно запуска открыто.'); }
  } finally {
    if (current === sequence) form.classList.remove('loading');
  }
}

form.addEventListener('submit', event => { event.preventDefault(); analyze(true); });
input.addEventListener('input', () => {
  stopScroll();
  sequence++;
  form.classList.remove('loading');
  resultCard.hidden = true;
  setMessage('');
});
document.querySelectorAll('.example').forEach(button => button.addEventListener('click', () => {
  input.value = button.dataset.url;
  input.dispatchEvent(new Event('input', {bubbles:true}));
  input.focus();
}));
document.getElementById('clear-history').addEventListener('click', () => {
  localStorage.removeItem(historyKey);
  renderHistory();
});
renderHistory();
loadFeedStatus();
if (location.protocol === 'file:') {
  setMessage('Чтобы проверка работала, запустите start.bat и откройте локальный адрес сервиса.');
}

const beachFooter = document.querySelector('.site-footer');
if (beachFooter && 'IntersectionObserver' in window) {
  beachFooter.classList.add('beach-ready');
  const beachObserver = new IntersectionObserver(([entry]) => {
    if (entry.isIntersecting) {
      beachFooter.classList.add('beach-in-view');
      beachObserver.disconnect();
    }
  }, {threshold:.12});
  beachObserver.observe(beachFooter);
}
