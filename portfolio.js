/* ============================================================
   ANDY // CYBER COMMAND CENTER  — logic
   Vanilla JS. Preserves original architecture:
   - HTB stats fetch (htb-stats.json) w/ fallback
   - Blue Team dynamic card loader (Blueteam/blueteam-writeups.json)
   - global cross-section live search
   - particle canvas w/ per-section colour shift
   Adds: interactive terminal emulator + section-reactive theming.
   ============================================================ */

/* ─────────────────────────────────────────────
   SECTION SWITCHING  (+ global accent theming)
───────────────────────────────────────────── */
const journeyColors = {
  home:      { r: 159, g: 239, b: 0   },
  redteam:   { r: 255, g: 51,  b: 75  },
  blueteam:  { r: 0,   g: 191, b: 255 },
  forensics: { r: 168, g: 85,  b: 247 }
};
let activeColor = journeyColors.home;

function switchJourney(journey) {
  document.querySelectorAll('.journey-btn').forEach(btn => btn.classList.remove('active'));
  const btn = document.querySelector(`.journey-btn.${journey}`);
  if (btn) btn.classList.add('active');

  document.querySelectorAll('.content-section').forEach(s => {
    s.classList.remove('active');
    s.style.display = '';
  });
  const content = document.getElementById(`${journey}-content`);
  if (content) content.classList.add('active');

  // global accent follows the active section
  document.documentElement.setAttribute('data-section', journey);
  activeColor = journeyColors[journey] || journeyColors.home;

  const search = document.getElementById('writeup-search');
  if (search) search.value = '';
  const count = document.getElementById('search-count');
  if (count) count.textContent = '';

  const target = document.getElementById('journey');
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ─────────────────────────────────────────────
   HTB STATS
───────────────────────────────────────────── */
let liveStats = { rank: 'Script Kiddie', finalScore: 36, boxes: 14, writeups: 6 };

async function loadHTBStats() {
  try {
    const response = await fetch('./htb-stats.json?t=' + Date.now());
    if (!response.ok) throw new Error('Failed to fetch stats file');
    liveStats = await response.json();
  } catch (error) {
    /* keep fallback liveStats */
  }
  updateStatsDisplay(liveStats);
}

function updateStatsDisplay(stats) {
  setTimeout(() => {
    animateNumber(document.getElementById('boxes-pwned'), stats.boxes, '');
    animateNumber(document.getElementById('writeups-count'), stats.writeups || 6, '');
    animateText(document.getElementById('htb-rank'), stats.rank);
    animateNumber(document.getElementById('htb-score'), stats.finalScore || stats.points || 36, '');
  }, 400);
}

function animateNumber(element, targetValue, suffix = '') {
  if (!element) return;
  element.classList.remove('loading');
  const duration = 1400;
  const increment = targetValue / (duration / 16);
  let currentValue = 0;
  const timer = setInterval(() => {
    currentValue += increment;
    if (currentValue >= targetValue) {
      element.textContent = targetValue.toLocaleString() + suffix;
      clearInterval(timer);
    } else {
      element.textContent = Math.floor(currentValue).toLocaleString() + suffix;
    }
  }, 16);
}

function animateText(element, text) {
  if (!element) return;
  element.classList.remove('loading');
  element.style.opacity = '0';
  setTimeout(() => {
    element.textContent = text;
    element.style.opacity = '1';
    element.style.transition = 'opacity 0.35s ease';
  }, 200);
}

/* ─────────────────────────────────────────────
   BLUE TEAM — DYNAMIC CARD LOADER
   Reads Blueteam/blueteam-writeups.json, splits by "series"
───────────────────────────────────────────── */
async function loadBlueTeamWriteups() {
  try {
    const res = await fetch('Blueteam/blueteam-writeups.json?t=' + Date.now());
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const writeups = await res.json();

    const socWriteups = writeups
      .filter(w => w.series === 'SOC Training')
      .sort((a, b) => (a.day || 0) - (b.day || 0));
    const cdWriteups = writeups
      .filter(w => w.series === 'CyberDefenders')
      .sort((a, b) => (a.day || 0) - (b.day || 0));

    renderBlueCards('soc-grid', socWriteups, {
      comingSoonDesc: 'Future writeups will cover threat hunting methodologies, SIEM rule tuning, EDR deep visibility queries, and live incident response exercises from Locked Shields.',
      comingSoonTags: ['Threat Hunting', 'SentinelOne', 'EDR', 'Locked Shields']
    });
    renderBlueCards('cd-grid', cdWriteups, {
      comingSoonDesc: 'Upcoming labs will cover memory forensics, SIEM correlation rule building, malware traffic analysis, and cloud intrusion investigations.',
      comingSoonTags: ['Memory Forensics', 'Volatility', 'Cloud IR', 'Malware Traffic']
    });
  } catch (err) {
    console.warn('Could not load blue team writeups:', err);
    ['soc-grid', 'cd-grid'].forEach(id => {
      const grid = document.getElementById(id);
      if (!grid) return;
      grid.innerHTML = `
        <div class="bt-load-error">
          <i class="fas fa-plug"></i>
          Could not load writeups — make sure
          <code>Blueteam/blueteam-writeups.json</code> exists.
        </div>`;
    });
  }
}

function renderBlueCards(gridId, writeups, options) {
  const grid = document.getElementById(gridId);
  if (!grid) return;
  grid.innerHTML = '';

  writeups.forEach(w => {
    const card = document.createElement('article');
    card.className = 'writeup-card blue-card reveal';
    card.innerHTML = `
      <div class="writeup-header">
        <h3 class="writeup-title">${w.emoji || '📄'} ${w.title}</h3>
        <span class="difficulty soc">${w.badge}</span>
      </div>
      <div class="writeup-meta">
        <span><i class="fas fa-calendar"></i>${w.date}</span>
        <span><i class="fas fa-shield-alt"></i>${w.category}</span>
        <span><i class="fas fa-clock"></i>${w.timeLabel}</span>
      </div>
      <p class="writeup-description">${w.description}</p>
      <div class="writeup-tags">
        ${w.tags.map(t => `<span class="tag">${t}</span>`).join('')}
      </div>
      <a href="Blueteam/${w.url}" class="read-more">Read Writeup</a>
    `;
    observer.observe(card);
    grid.appendChild(card);
  });

  // Coming Soon placeholder
  const cs = document.createElement('article');
  cs.className = 'writeup-card blue-card reveal';
  cs.style.opacity = '0.55';
  cs.innerHTML = `
    <div class="writeup-header">
      <h3 class="writeup-title">🔜 More Coming Soon</h3>
      <span class="difficulty soc">TBA</span>
    </div>
    <div class="writeup-meta">
      <span><i class="fas fa-calendar"></i>In Progress</span>
      <span><i class="fas fa-shield-alt"></i>Blue Team</span>
    </div>
    <p class="writeup-description">${options.comingSoonDesc}</p>
    <div class="writeup-tags">
      ${options.comingSoonTags.map(t => `<span class="tag">${t}</span>`).join('')}
    </div>
    <span class="read-more disabled">Coming Soon</span>
  `;
  observer.observe(cs);
  grid.appendChild(cs);
}

/* ─────────────────────────────────────────────
   INTERSECTION OBSERVER (scroll-in reveal)
───────────────────────────────────────────── */
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('in');
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.12 });

/* ─────────────────────────────────────────────
   SMOOTH SCROLL for in-page anchors
───────────────────────────────────────────── */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    const target = document.querySelector(this.getAttribute('href'));
    if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  });
});

/* ─────────────────────────────────────────────
   INTERACTIVE TERMINAL EMULATOR
───────────────────────────────────────────── */
const TERM = {
  output: null,
  input: null,
  body: null,
  bootLines: [
    { cls: 'sys',  txt: 'cyberjourney_os v3.0 — secure boot' },
    { cls: 'ok',   txt: '[<b>  OK  </b>] initializing andy\'s cyber journey logs' },
    { cls: 'ok',   txt: '[<b>  OK  </b>] mounting /dev/htb' },
    { cls: 'ok',   txt: '[<b>  OK  </b>] firewall rules loaded' },
    { cls: 'ok',   txt: '[<b>  OK  </b>] offensive toolkit armed' },
    { cls: 'ok',   txt: '[<b>  OK  </b>] SOC sensors online' },
    { cls: 'warn', txt: '[<b> WARN </b>] coffee reserves low' },
    { cls: 'sys',  txt: '' },
    { cls: 'out',  txt: 'welcome, operator. type <span class="key">help</span> to list commands.' }
  ]
};

function termLine(html, cls = 'out') {
  const div = document.createElement('div');
  div.className = 'tline ' + cls;
  div.innerHTML = html;
  TERM.output.appendChild(div);
  TERM.body.scrollTop = TERM.body.scrollHeight;
  return div;
}

function bootSequence(i = 0) {
  if (i >= TERM.bootLines.length) {
    document.querySelector('.term-input-line').style.visibility = 'visible';
    TERM.input.focus();
    return;
  }
  const l = TERM.bootLines[i];
  termLine(l.txt || '&nbsp;', l.cls);
  setTimeout(() => bootSequence(i + 1), l.txt ? 230 : 90);
}

const TERM_CMDS = {
  help() {
    return [
      ['head', 'AVAILABLE COMMANDS'],
      ['out',  '<span class="key">about</span>      operator profile &amp; mission'],
      ['out',  '<span class="key">skills</span>     core competencies'],
      ['out',  '<span class="key">stats</span>      live HTB metrics'],
      ['out',  '<span class="key">whoami</span>     current session'],
      ['out',  '<span class="key">social</span>     external links'],
      ['out',  '<span class="key">redteam</span> · <span class="key">blueteam</span> · <span class="key">forensics</span>   jump to a section'],
      ['out',  '<span class="key">clear</span>      wipe the console']
    ];
  },
  about() {
    return [
      ['out', 'Andy — cybersecurity practitioner documenting a journey across'],
      ['out', 'offensive security, defensive operations, and digital forensics.'],
      ['out', 'Understanding attacks builds better defenders; forensics ties it all'],
      ['out', 'together by revealing the full story of what happened.']
    ];
  },
  skills() {
    return [
      ['head', 'CORE COMPETENCIES'],
      ['out', '<span class="dim">red  </span> Active Directory · Web Exploitation · Privilege Escalation'],
      ['out', '<span class="dim">blue </span> SIEM &amp; Log Analysis · Threat Hunting · Incident Response'],
      ['out', '<span class="dim">forx </span> Disk / Memory Forensics · Malware Analysis · Timeline Recon']
    ];
  },
  stats() {
    return [
      ['head', 'HTB METRICS'],
      ['out', `boxes pwned ...... <span class="key">${liveStats.boxes}</span>`],
      ['out', `writeups ......... <span class="key">${liveStats.writeups || 6}</span>`],
      ['out', `rank ............. <span class="key">${liveStats.rank}</span>`],
      ['out', `final score ...... <span class="key">${liveStats.finalScore || liveStats.points || 36}</span>`]
    ];
  },
  whoami() {
    return [['out', 'andy@htb · operator · clearance: <span class="key">curious</span>']];
  },
  social() {
    return [
      ['head', 'EXTERNAL LINKS'],
      ['out', 'github ..... <a href="https://github.com/ADN314" target="_blank" rel="noopener">github.com/ADN314</a>'],
      ['out', 'linkedin ... <a href="https://www.linkedin.com/in/anh-duy-nguyen-8240a2343/" target="_blank" rel="noopener">in/anh-duy-nguyen</a>'],
      ['out', 'htb ........ <a href="https://app.hackthebox.com/profile/1779650" target="_blank" rel="noopener">profile/1779650</a>']
    ];
  },
  redteam()   { switchJourney('redteam');   return [['out', 'switching context → <span class="key">red team</span> // offensive']]; },
  blueteam()  { switchJourney('blueteam');  return [['out', 'switching context → <span class="key">blue team</span> // defensive']]; },
  forensics() { switchJourney('forensics'); return [['out', 'switching context → <span class="key">forensics</span> // analysis']]; },
  ls() { return [['out', '<span class="key">redteam/</span>  <span class="key">blueteam/</span>  <span class="key">forensics/</span>  about.txt  contact.txt']]; },
  sudo() { return [['err', 'nice try. this incident will be reported. 🚓']]; },
  clear() { TERM.output.innerHTML = ''; return null; }
};

function runCommand(raw) {
  const cmd = raw.trim().toLowerCase();
  termLine(`<span class="p">andy@htb</span><span class="dim">:~$</span> ${escapeHtml(raw)}`, 'cmd');
  if (!cmd) return;
  const fn = TERM_CMDS[cmd];
  if (!fn) {
    termLine(`command not found: <span class="dim">${escapeHtml(cmd)}</span> — type <span class="key">help</span>`, 'err');
    return;
  }
  const result = fn();
  if (result) result.forEach(([cls, html]) => termLine(html, cls));
}

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c]));
}

function initTerminal() {
  TERM.output = document.getElementById('terminal-output');
  TERM.input  = document.getElementById('terminal-input');
  TERM.body   = document.getElementById('terminal-body');
  if (!TERM.output) return;

  const history = []; let hIdx = -1;
  TERM.input.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const v = TERM.input.value;
      if (v.trim()) { history.push(v); hIdx = history.length; }
      runCommand(v);
      TERM.input.value = '';
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (hIdx > 0) { hIdx--; TERM.input.value = history[hIdx]; }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (hIdx < history.length - 1) { hIdx++; TERM.input.value = history[hIdx]; }
      else { hIdx = history.length; TERM.input.value = ''; }
    }
  });
  TERM.body.addEventListener('click', () => TERM.input.focus());
  bootSequence();
}

/* ─────────────────────────────────────────────
   HERO TAGLINE TYPEWRITER
───────────────────────────────────────────── */
function typeTagline() {
  const el = document.getElementById('hero-tag');
  if (!el) return;
  const text = el.getAttribute('data-text') || el.textContent;
  el.innerHTML = '';
  let i = 0;
  (function type() {
    if (i < text.length) {
      el.insertAdjacentText('beforeend', text.charAt(i));
      i++;
      setTimeout(type, 34);
    } else {
      const c = document.createElement('span');
      c.className = 'caret'; c.textContent = '▮';
      el.appendChild(c);
    }
  })();
}

/* ─────────────────────────────────────────────
   SHOW MORE / LESS  (Red Team grid)
───────────────────────────────────────────── */
function toggleWriteups() {
  const grid = document.getElementById('htb-grid');
  const btn  = document.getElementById('show-more-btn');
  const nowCapped = grid.classList.toggle('capped');
  if (nowCapped) {
    btn.innerHTML = 'Show More <i class="fas fa-chevron-down"></i>';
    btn.classList.remove('expanded');
    grid.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } else {
    btn.innerHTML = 'Show Less <i class="fas fa-chevron-up"></i>';
    btn.classList.add('expanded');
  }
}

/* ─────────────────────────────────────────────
   GLOBAL SEARCH
───────────────────────────────────────────── */
function initSearch() {
  const input = document.getElementById('writeup-search');
  if (!input) return;
  input.addEventListener('input', function () {
    const q = this.value.toLowerCase().trim();

    document.querySelectorAll('.content-section').forEach(s => {
      if (q.length > 0) s.style.display = 'block';
      else s.style.display = s.classList.contains('active') ? 'block' : 'none';
    });

    let shown = 0;
    document.querySelectorAll('.writeup-card').forEach(card => {
      if (!q) { card.classList.remove('search-hidden'); shown++; return; }
      const text = card.textContent.toLowerCase();
      if (text.includes(q)) { card.classList.remove('search-hidden'); shown++; }
      else card.classList.add('search-hidden');
    });

    const counter = document.getElementById('search-count');
    if (counter) counter.textContent = q ? shown + ' result' + (shown !== 1 ? 's' : '') : '';
  });
}

/* ─────────────────────────────────────────────
   PARTICLE BACKGROUND
───────────────────────────────────────────── */
const canvas = document.getElementById('particle-canvas');
const ctx = canvas.getContext('2d');
let particles = [];
let mouse = { x: null, y: null, radius: 150 };

function resizeCanvas() { canvas.width = window.innerWidth; canvas.height = window.innerHeight; }
resizeCanvas();
window.addEventListener('resize', resizeCanvas);
window.addEventListener('mousemove', e => { mouse.x = e.x; mouse.y = e.y; });
window.addEventListener('mouseout', () => { mouse.x = null; mouse.y = null; });

class Particle {
  constructor() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.size = Math.random() * 1.8 + 0.6;
    this.density = (Math.random() * 30) + 1;
    this.vx = (Math.random() - 0.5) * 0.45;
    this.vy = (Math.random() - 0.5) * 0.45;
  }
  draw() {
    const { r, g, b } = activeColor;
    ctx.fillStyle = `rgba(${r},${g},${b},0.5)`;
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    ctx.fill();
  }
  update() {
    this.x += this.vx; this.y += this.vy;
    if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
    if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    if (mouse.x != null && mouse.y != null) {
      let dx = mouse.x - this.x, dy = mouse.y - this.y;
      let distance = Math.sqrt(dx * dx + dy * dy);
      if (distance < mouse.radius) {
        let force = (mouse.radius - distance) / mouse.radius;
        this.x -= (dx / distance) * force * this.density * 0.55;
        this.y -= (dy / distance) * force * this.density * 0.55;
      }
    }
  }
}

function initParticles() {
  particles = [];
  const n = Math.floor((canvas.width * canvas.height) / 16000);
  for (let i = 0; i < n; i++) particles.push(new Particle());
}

function connect() {
  for (let a = 0; a < particles.length; a++) {
    for (let b = a + 1; b < particles.length; b++) {
      let dx = particles[a].x - particles[b].x, dy = particles[a].y - particles[b].y;
      let d = Math.sqrt(dx * dx + dy * dy);
      if (d < 118) {
        const { r, g, b: cb } = activeColor;
        ctx.strokeStyle = `rgba(${r},${g},${cb},${(1 - d / 118) * 0.28})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(particles[a].x, particles[a].y);
        ctx.lineTo(particles[b].x, particles[b].y);
        ctx.stroke();
      }
    }
  }
}

function connectMouse() {
  if (mouse.x == null) return;
  for (let i = 0; i < particles.length; i++) {
    let dx = mouse.x - particles[i].x, dy = mouse.y - particles[i].y;
    let d = Math.sqrt(dx * dx + dy * dy);
    if (d < mouse.radius) {
      const { r, g, b } = activeColor;
      ctx.strokeStyle = `rgba(${r},${g},${b},${(1 - d / mouse.radius) * 0.55})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(mouse.x, mouse.y);
      ctx.lineTo(particles[i].x, particles[i].y);
      ctx.stroke();
    }
  }
}

function animate() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  particles.forEach(p => { p.update(); p.draw(); });
  connect(); connectMouse();
  requestAnimationFrame(animate);
}
initParticles(); animate();
window.addEventListener('resize', initParticles);

/* ─────────────────────────────────────────────
   BOOT
───────────────────────────────────────────── */
document.querySelectorAll('.writeup-card, .journey-card, .tool-card').forEach(el => {
  el.classList.add('reveal');
  observer.observe(el);
});

// hide show-more if 6 or fewer red team cards
(function () {
  const grid = document.getElementById('htb-grid');
  const wrap = document.getElementById('show-more-wrap');
  if (grid && wrap && grid.querySelectorAll('.writeup-card').length <= 6) wrap.style.display = 'none';
})();

initSearch();

window.addEventListener('load', () => {
  initTerminal();
  typeTagline();
  setTimeout(loadHTBStats, 600);
  loadBlueTeamWriteups();
});
