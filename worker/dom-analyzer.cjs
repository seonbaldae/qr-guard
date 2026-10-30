'use strict';

// Read-only, post-render inspection. This module never navigates or submits.
function createDomAnalyzer(page, options = {}) {
  const cap = (v, fallback, max) => Number.isInteger(v) && v >= 0 ? Math.min(v, max) : fallback;
  const maxFrames = cap(options.maxFrames, 10, 50);
  const maxForms = cap(options.maxForms, 20, 100);
  const maxFields = cap(options.maxFields, 200, 1000);
  const maxTitleLength = cap(options.maxTitleLength, 200, 500);
  const official = typeof options.officialDomain === 'string' ? options.officialDomain.toLowerCase() : null;
  const resolver = options.resolveRegisteredDomain;
  let current = null, limits = [], observations = [], stopped = false, pending = null;
  const copy = x => JSON.parse(JSON.stringify(x));
  const addLimit = x => { if (!limits.includes(x)) limits.push(x); };

  async function run() {
    current = null; limits = []; observations = [];
    addLimit('Only accessible rendered DOM and open shadow roots are inspected; closed shadow roots are not observable.');
    let frames;
    try { frames = page.frames(); if (!Array.isArray(frames)) throw Error(); }
    catch { addLimit('Frame enumeration failed; DOM inspection incomplete.'); return null; }
    if (frames.length > maxFrames) addLimit('Frame limit reached; DOM inspection incomplete.');
    if (!frames.length) addLimit('No accessible frames; DOM inspection incomplete.');
    let inspected = 0, fields = 0, formsSeen = 0, password = 0, title = null, incomplete = frames.length > maxFrames, fieldIncomplete = frames.length > maxFrames;
    const forms = [], types = new Set();
    for (let i = 0; i < Math.min(frames.length, maxFrames); i++) {
      if (stopped) { addLimit('Inspection stopped before completion.'); incomplete = true; fieldIncomplete = true; break; }
      let data;
      try {
        data = await frames[i].evaluate(({fieldBudget, formBudget, titleLimit, main}) => {
          let fieldCount = 0, formCount = 0, passwordCount = 0, truncatedFields = false, truncatedForms = false, truncatedNodes = false;
          const detected = [], formData = [], stack = [document];
          let visited = 0;
          while (stack.length) {
            if (++visited > 20000) { truncatedNodes = true; break; }
            const node = stack.pop();
            const tag = node.tagName;
            if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') {
              if (fieldCount >= fieldBudget) truncatedFields = true;
              else {
                fieldCount++;
                const attr = name => (node.getAttribute(name) || '').slice(0, 128).toLowerCase();
                const type = attr('type'), ac = attr('autocomplete');
                if (type === 'password') { passwordCount++; if (!detected.includes('password')) detected.push('password'); }
                const hints = [attr('name'), attr('id'), attr('placeholder'), attr('aria-label')].join(' ');
                if (/(^|\s)one-time-code(\s|$)/.test(ac) || /(?:^|[^a-z0-9])(?:otp|one[-_ ]time[-_ ]code|verification[-_ ]code)(?:$|[^a-z0-9])/.test(hints)) {
                  if (!detected.includes('otp')) detected.push('otp');
                }
                if (/(^|\s)cc-number(\s|$)/.test(ac) && !detected.includes('payment_card')) detected.push('payment_card');
              }
            }
            if (tag === 'FORM') {
              formCount++;
              if (formData.length >= formBudget) truncatedForms = true;
              else {
                const rawMethod = (node.getAttribute('method') || '').toLowerCase();
                const method = rawMethod === 'post' || rawMethod === 'dialog' ? rawMethod : 'get';
                let actionHost = null;
                try {
                  // Missing/empty action targets the document, not a different <base> host.
                  const url = new URL(node.getAttribute('action') || document.URL || document.baseURI, document.baseURI);
                  if (url.protocol === 'http:' || url.protocol === 'https:') actionHost = url.hostname || null;
                } catch {}
                formData.push({method, actionHost});
              }
            }
            const children = node.children;
            if (children) for (let j = children.length - 1; j >= 0; j--) {
              if (stack.length >= 20000) { truncatedNodes = true; break; }
              stack.push(children[j]);
            }
            if (node.shadowRoot) stack.push(node.shadowRoot);
          }
          let pageTitle = null;
          if (main && typeof document.title === 'string') {
            let text = document.title.slice(0, Math.max(titleLimit * 4, 500));
            text = text.replace(/https?:\/\/\S+|www\.\S+/gi, '[redacted]')
              .replace(/\b(?:token|secret|password|authorization|api[_-]?key|code)\s*[:=]\s*\S+/gi, '[redacted]')
              .replace(/[\x00-\x1f\x7f]/g, ' ').trim();
            pageTitle = text.slice(0, titleLimit) || null;
          }
          return {fieldCount, formCount, passwordCount, detected, formData, pageTitle, truncatedFields, truncatedForms, truncatedNodes};
        }, {fieldBudget: Math.max(0, maxFields - fields), formBudget: Math.max(0, maxForms - forms.length), titleLimit: maxTitleLength, main: i === 0});
      } catch {
        addLimit('A frame was detached or inaccessible; DOM inspection incomplete.'); incomplete = true; fieldIncomplete = true; continue;
      }
      inspected++; fields += data.fieldCount; formsSeen += data.formCount; password += data.passwordCount;
      if (i === 0) title = data.pageTitle;
      for (const type of data.detected) types.add(type);
      forms.push(...data.formData);
      if (data.truncatedFields) { addLimit('Field limit reached; DOM inspection incomplete.'); incomplete = true; fieldIncomplete = true; }
      if (data.truncatedForms) { addLimit('Form limit reached; form observations incomplete.'); incomplete = true; }
      if (data.truncatedNodes) { addLimit('DOM node limit reached; DOM inspection incomplete.'); incomplete = true; fieldIncomplete = true; }
    }
    observations.push({kind: 'dom_inspection', inspectedFrames: inspected, inspectedFields: fields, observedForms: formsSeen, incomplete});
    if (official && typeof resolver === 'function') {
      for (const form of forms) {
        if (!form.actionHost) continue;
        try {
          const domain = await resolver(form.actionHost);
          if (typeof domain === 'string' && domain) observations.push({kind: 'form_action_domain_comparison', actionHost: form.actionHost, mismatch: domain.toLowerCase() !== official});
          else addLimit('Registered-domain comparison unavailable for at least one form.');
        } catch { addLimit('Registered-domain comparison unavailable for at least one form.'); }
      }
    } else addLimit('Official-domain comparison unavailable without a verified domain and resolver.');
    if (!inspected || (fieldIncomplete && password === 0)) return null;
    current = {pageTitle: title, passwordFieldCount: password, sensitiveFieldTypes: ['password', 'otp', 'payment_card'].filter(x => types.has(x)), forms};
    return copy(current);
  }
  return {
    collect() {
      if (stopped) return Promise.resolve(null);
      if (!pending) pending = run().finally(() => { pending = null; });
      return pending.then(copy);
    },
    result: () => copy(current),
    limitations: () => copy(limits),
    observations: () => copy(observations),
    stop() { stopped = true; },
  };
}
module.exports = { createDomAnalyzer };
