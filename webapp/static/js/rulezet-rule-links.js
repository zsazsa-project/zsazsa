/**
 * rulezet-rule-links.js: a "view rule" button next to every Rulezet rule
 * referenced on a saved product.
 *
 * A product stores a rule as the line "title — url" the wizard appended, so a
 * detail page has the name and the link but not the rule itself. This finds the
 * links and puts a button beside each one that fetches the rule through
 * /api/rulezet-rule and shows it in the shared Rulezet modal, the same view the
 * search results open (window.zsazsaShowRuleCode).
 *
 * The containers are marked with data-rulezet-rules because the five products
 * render that field three different ways: raw text in a <p> (daily briefing),
 * list items through the bullets() macro (flash intel alert, vulnerability
 * advisory, detection engineering request) and client-side Markdown (threat
 * actor profile). Working on the rendered text covers all of them without
 * touching any of the three.
 */
(function () {
  // Rulezet's own rule permalink, whichever instance produced it. The id is
  // what /api/rulezet-rule takes; the rest of the URL is left alone.
  const RULE_URL_RE = /https?:\/\/[^\s<>"']*\/rule\/detail_rule\/(\d+)/;

  function viewButton(ruleId) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-xs btn-link p-0 ms-1 align-baseline zs-rule-view-btn';
    btn.dataset.ruleId = ruleId;
    btn.title = 'View this rule';
    btn.setAttribute('aria-label', 'View this rule');
    btn.innerHTML = '<i class="fas fa-eye fa-xs"></i>';
    return btn;
  }

  /* Walks the text of a container and drops a button in after each rule link.
     splitText keeps everything around the match untouched, so the Markdown and
     the list markup the products already render survive as they are. */
  function addButtons(container) {
    // Done once per container. The threat actor profile renders its Markdown
    // from an inline script and calls this itself, which happens while the page
    // is still parsing, so the sweep below reaches the same container later and
    // would otherwise leave two buttons on every rule.
    if (container.dataset.rulezetLinked) return;
    container.dataset.rulezetLinked = '1';

    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
    const nodes = [];
    let node;
    while ((node = walker.nextNode())) nodes.push(node);

    nodes.forEach(function (textNode) {
      let current = textNode;
      let match;
      while (current && (match = RULE_URL_RE.exec(current.nodeValue))) {
        const end = match.index + match[0].length;
        // The tail becomes its own node, and the button goes between the two.
        const tail = current.splitText(end);
        // Unless the link is a real <a>: the threat actor profile renders its
        // recommendations with marked, whose GFM autolinker wraps a bare URL,
        // and a button inside a link is neither valid markup nor its own
        // control. It goes after the anchor there.
        const parent = current.parentNode;
        const anchor = parent.closest('a');
        if (anchor && container.contains(anchor) && anchor !== container) {
          anchor.parentNode.insertBefore(viewButton(match[1]), anchor.nextSibling);
        } else {
          parent.insertBefore(viewButton(match[1]), tail);
        }
        current = tail;
      }
    });
  }

  function showRule(btn) {
    const original = btn.innerHTML;
    btn.disabled = true;
    btn.title = 'View this rule';
    btn.classList.remove('text-danger');
    btn.innerHTML = '<i class="fas fa-spinner fa-spin fa-xs"></i>';
    fetch(SCRIPT_ROOT + '/api/rulezet-rule', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.content || '',
      },
      body: JSON.stringify({ rule_id: btn.dataset.ruleId }),
    })
      .then(zsazsaReadJson)
      .then(function (data) {
        if (!data.ok) throw new Error(data.error || 'Rulezet did not return that rule.');
        window.zsazsaShowRuleCode(data.rule);
      })
      .catch(function (err) {
        // No modal for a rule that could not be read: the link beside the
        // button still goes to Rulezet itself.
        btn.title = 'Could not load this rule: ' + zsazsaErrorText(err);
        btn.classList.add('text-danger');
      })
      .finally(function () {
        btn.disabled = false;
        btn.innerHTML = original;
      });
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-rulezet-rules]').forEach(addButtons);
  });

  document.addEventListener('click', function (ev) {
    const btn = ev.target.closest('.zs-rule-view-btn');
    if (btn) {
      ev.preventDefault();
      showRule(btn);
    }
  });

  // For a page that builds its rule links itself and cannot wait for the sweep
  // above: the threat actor profile renders its recommendations from Markdown
  // while the page is still parsing, so its links do not exist yet when this
  // file is loaded, and no longer need adding by the time DOMContentLoaded
  // fires.
  window.zsazsaAddRulezetRuleButtons = addButtons;
})();
