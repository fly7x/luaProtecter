// ---------------------------------------------------------------------------
// Hero transform panel: types out the "after" code one token at a time.
// ---------------------------------------------------------------------------
(function () {
  var target = document.getElementById('out-stream');
  if (!target) return;

  // Each token is typed in order; cls = null means plain/whitespace text.
  var tokens = [
    { t: 'local', c: 'tok-kw' }, { t: ' ', c: null },
    { t: '_0x4e2', c: 'tok-mut' }, { t: ' = ', c: null },
    { t: 'game', c: 'tok-fn' }, { t: ':', c: null }, { t: 'GetService', c: 'tok-fn' },
    { t: '(', c: null }, { t: '"\\80\\108\\97\\121\\101\\114\\115"', c: 'tok-str' }, { t: ')\n', c: null },

    { t: 'local', c: 'tok-kw' }, { t: ' ', c: null },
    { t: '_0x1a9', c: 'tok-mut' }, { t: ' = ', c: null },
    { t: '(', c: null }, { t: '19', c: 'tok-num' }, { t: ' + ', c: null }, { t: '6', c: 'tok-num' }, { t: ')\n\n', c: null },

    { t: 'local', c: 'tok-kw' }, { t: ' ', c: null }, { t: 'function', c: 'tok-kw' }, { t: ' ', c: null },
    { t: '_0xb77', c: 'tok-mut' }, { t: '(', c: null }, { t: '_0xc3', c: 'tok-mut' }, { t: ')\n  ', c: null },
    { t: 'local', c: 'tok-kw' }, { t: ' ', c: null }, { t: '_0xf1', c: 'tok-mut' }, { t: ' = ', c: null },
    { t: '_0xc3', c: 'tok-mut' }, { t: ':', c: null }, { t: 'FindFirstChild', c: 'tok-fn' }, { t: '(', c: null },
    { t: '"\\108\\101\\97\\100\\101\\114\\115\\116\\97\\116\\115"', c: 'tok-str' }, { t: ')\n  ', c: null },
    { t: 'if', c: 'tok-kw' }, { t: ' _0xf1 ', c: null }, { t: 'then', c: 'tok-kw' }, { t: '\n    ', c: null },
    { t: '_0xf1', c: 'tok-mut' }, { t: '.Coins.Value += _0x1a9\n  ', c: null },
    { t: 'end', c: 'tok-kw' }, { t: '\n', c: null }, { t: 'end', c: 'tok-kw' }, { t: '\n\n', c: null },

    { t: '_0x4e2', c: 'tok-mut' }, { t: '.PlayerAdded:Connect(_0xb77)', c: null }
  ];

  var ti = 0, ci = 0;
  var speed = 14; // ms per character

  function step() {
    if (ti >= tokens.length) return;
    var tok = tokens[ti];

    if (ci === 0) {
      var span = document.createElement('span');
      if (tok.c) span.className = tok.c;
      span.dataset.full = tok.t;
      span.textContent = '';
      target.appendChild(span);
    }

    var current = target.lastChild;
    var full = tok.t;
    ci++;
    current.textContent = full.slice(0, ci);

    if (ci >= full.length) {
      ti++;
      ci = 0;
    }

    window.setTimeout(step, speed);
  }

  // Respect reduced-motion: render instantly instead of animating.
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) {
    tokens.forEach(function (tok) {
      var span = document.createElement('span');
      if (tok.c) span.className = tok.c;
      span.textContent = tok.t;
      target.appendChild(span);
    });
  } else {
    // Small delay so the panel settles before typing starts.
    window.setTimeout(step, 400);
  }
})();

// ---------------------------------------------------------------------------
// Docs page: scrollspy for the left nav + smooth in-page jumps.
// ---------------------------------------------------------------------------
(function () {
  var sections = document.querySelectorAll('.doc-section[id]');
  var links = document.querySelectorAll('.docs-side a[href^="#"]');
  if (!sections.length || !links.length) return;

  var linkByHash = {};
  links.forEach(function (l) { linkByHash[l.getAttribute('href')] = l; });

  function setActive(id) {
    links.forEach(function (l) { l.classList.remove('active'); });
    var active = linkByHash['#' + id];
    if (active) active.classList.add('active');
  }

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) setActive(entry.target.id);
    });
  }, { rootMargin: '-15% 0px -70% 0px', threshold: 0 });

  sections.forEach(function (s) { observer.observe(s); });
})();
