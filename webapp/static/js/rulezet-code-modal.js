/**
 * rulezet-code-modal.js — syntax-highlighted rule viewer, as the "detail" view
 * of the one shared Rulezet modal (its shell — including the #zs-rc-* elements
 * this file populates — is built by rulezet-search-modal.js's ensureModal()).
 * Switching between the results table and a rule's code is a view toggle
 * inside that single modal (zsazsaShowRulezetSearchView/DetailView), never a
 * close-then-reopen, so there is no transition or backdrop flicker between
 * them.
 *
 * The rule-format to highlight.js-language mapping and the custom YARA/
 * Suricata/TOML grammars (hljs-lang/*.js) are ported from Rulezet's own code
 * viewer (github.com/ngsoti/rulezet-core, AGPL-3.0), so a rule looks the same
 * whether viewed on Rulezet or inside this modal. highlight.js itself is the
 * cdnjs "common" build, loaded on first use rather than with the page.
 */
(function () {
  const HLJS_LANG_DIR = SCRIPT_ROOT + '/static/js/hljs-lang/';

  // Rule format -> highlight.js language.
  const LANG_ALIASES = {
    nse: 'lua',
    sigma: 'yaml',
    atr: 'yaml',
    kunai: 'yaml',
    splunk: 'yaml',
    wazuh: 'xml',
    zeek: 'text',
    crs: 'text',
    nova: 'text',
    kql: 'sql',
    elastic: 'toml',
    sagan: 'suricata',
  };

  // Asks the loaded highlight.js rather than a hardcoded list: the cdnjs
  // common build does not carry every language a rule format could map to
  // (http and nginx, for one), and a language it lacks must fall back to
  // plain text instead of making hljs.highlight() throw.
  function detectLanguage(hljs, format) {
    const hint = (format || '').toLowerCase();
    const mapped = LANG_ALIASES[hint] || hint;
    return mapped && hljs.getLanguage(mapped) ? mapped : 'plaintext';
  }

  let hljsReady = null;

  // Checked against listLanguages(), the registered grammars, and not with
  // getLanguage(), which also resolves aliases: the common build aliases
  // "toml" to its INI grammar, so getLanguage('toml') is truthy and the real
  // TOML grammar would never be registered. A grammar registered under the
  // name itself wins over an alias of that name.
  async function registerExtraLanguages(hljs) {
    const registered = hljs.listLanguages();
    if (!registered.includes('yara')) {
      const { default: yaraLanguage } = await import(HLJS_LANG_DIR + 'hljs-yara.js');
      hljs.registerLanguage('yara', yaraLanguage);
    }
    if (!registered.includes('suricata')) {
      const { default: suricataLanguage } = await import(HLJS_LANG_DIR + 'hljs-suricata.js');
      hljs.registerLanguage('suricata', suricataLanguage);
    }
    if (!registered.includes('toml')) {
      const { default: tomlLanguage } = await import(HLJS_LANG_DIR + 'hljs-toml.js');
      hljs.registerLanguage('toml', tomlLanguage);
    }
  }

  function loadHljs() {
    if (hljsReady) return hljsReady;
    if (window.hljs) {
      hljsReady = registerExtraLanguages(window.hljs).then(() => window.hljs);
      return hljsReady;
    }
    hljsReady = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js';
      s.crossOrigin = 'anonymous';
      s.referrerPolicy = 'no-referrer';
      s.onload = () => registerExtraLanguages(window.hljs).then(() => resolve(window.hljs));
      s.onerror = () => reject(new Error('highlight.js failed to load'));
      document.head.appendChild(s);
    });
    return hljsReady;
  }

  function esc(s) {
    // Quotes too: esc() output also lands inside attribute values.
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // Elements live in the shared modal shell (rulezet-search-modal.js's
  // ensureModal()) — grabbed lazily since zsazsaShowRuleCode is only ever
  // called after a search has already built that shell.
  let els = null;
  function elements() {
    if (els) return els;
    const modalEl = document.getElementById('zs-rulezet-modal');
    els = {
      codeEl: modalEl.querySelector('#zs-rc-code'),
      titleEl: modalEl.querySelector('#zs-rc-title'),
      badgeEl: modalEl.querySelector('#zs-rc-badge'),
      metaEl: modalEl.querySelector('#zs-rc-meta'),
      addBtn: modalEl.querySelector('#zs-rc-add'),
      openBtn: modalEl.querySelector('#zs-rc-open'),
      backBtn: modalEl.querySelector('#zs-rc-back'),
    };
    return els;
  }

  // One icon + [label, value] identification field per rule, so a search
  // returning many similarly-titled rules (e.g. 140 hits for a common
  // technique) can be told apart before adding one to the product.
  function metaField(icon, label, value) {
    if (!value) return '';
    return `
      <div class="zs-rc-meta-item">
        <i class="fas ${icon} zs-rc-meta-icon"></i>
        <div class="zs-rc-meta-text">
          <div class="zs-rc-meta-label">${esc(label)}</div>
          <div class="zs-rc-meta-value">${esc(value)}</div>
        </div>
      </div>`;
  }

  function renderMeta(metaEl, rule) {
    const matches = (rule.cve_ids || []).concat(rule.matched_techniques || []);
    metaEl.innerHTML = [
      metaField('fa-hashtag', 'ID', rule.id),
      metaField('fa-fingerprint', 'UUID', rule.uuid),
      metaField('fa-code-branch', 'Source', rule.source),
      metaField('fa-scale-balanced', 'License', rule.license),
      metaField('fa-user', 'Author', rule.author),
      metaField('fa-clock', 'Last modified', rule.last_modif),
      metaField('fa-star', 'Quality score', rule.quality_score != null ? rule.quality_score : ''),
      metaField('fa-bullseye', 'Matches', matches.join(', ')),
    ].join('') || '<span class="text-muted small">No metadata returned for this rule.</span>';
  }

  // rule: {title, format, url, content}. targetTextareaEl: textarea an "Add"
  // click appends "title — url" to; omit to hide the Add button (nothing to
  // add it to). onAdded: optional callback fired after a successful Add (e.g.
  // remove the row). onBack: optional callback shown as a "←" header button
  // (e.g. switch back to the search view this rule was opened from).
  window.zsazsaShowRuleCode = function (rule, targetTextareaEl, onAdded, onBack) {
    const e = elements();
    e.titleEl.textContent = rule.title || 'Untitled rule';
    e.badgeEl.textContent = rule.format || '?';
    e.openBtn.href = rule.url || '#';
    renderMeta(e.metaEl, rule);
    e.codeEl.className = 'hljs';
    e.codeEl.textContent = rule.content || '(no content returned)';

    e.addBtn.style.display = targetTextareaEl ? '' : 'none';
    e.addBtn.onclick = function () {
      if (!targetTextareaEl) return;
      zsazsaAddRuleReference(rule, targetTextareaEl);
      if (onAdded) onAdded();
      // Came from the search table (a "back" target exists): return to it
      // instead of leaving the analyst with everything closed.
      if (onBack) onBack();
    };

    e.backBtn.style.display = onBack ? '' : 'none';
    e.backBtn.onclick = function () { if (onBack) onBack(); };

    zsazsaShowRulezetDetailView();

    loadHljs().then(function (hljs) {
      const lang = detectLanguage(hljs, rule.format);
      try {
        const res = lang === 'plaintext'
          ? { value: esc(rule.content || '') }
          : hljs.highlight(rule.content || '', { language: lang, ignoreIllegals: true });
        e.codeEl.innerHTML = res.value;
      } catch (_) {
        e.codeEl.textContent = rule.content || '(no content returned)';
      }
    }).catch(function () {
      // highlight.js failed to load: plain text is still shown (textContent set above).
    });
  };
})();
