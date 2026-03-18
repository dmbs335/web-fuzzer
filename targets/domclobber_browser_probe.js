/**
 * DOM Clobbering browser probe — runs inside Playwright page.evaluate().
 * Probes all iframes on the page for Named Property Visibility behavior.
 */
(function() {
  const frames = document.querySelectorAll('iframe');
  const results = [];

  for (let i = 0; i < frames.length; i++) {
    const frame = frames[i];
    let doc, win;
    try {
      doc = frame.contentDocument;
      win = frame.contentWindow;
    } catch(e) {
      results.push({ id: i, error: 'access_denied', probes: {} });
      continue;
    }
    if (!doc || !win) {
      results.push({ id: i, error: 'no_document', probes: {} });
      continue;
    }

    // Get target property names from data attribute
    const props = JSON.parse(frame.dataset.props || '[]');
    const probes = {};

    for (const prop of props) {
      probes[prop] = probeProp(doc, win, prop);
    }

    results.push({ id: i, error: null, probes });
  }

  return results;

  function probeProp(doc, win, name) {
    const r = {
      // Document-level access
      doc_type: 'undefined',
      doc_constructor: null,
      doc_toString: null,
      doc_is_collection: false,
      doc_collection_length: null,
      doc_proto_chain: [],

      // Window-level access
      win_type: 'undefined',
      win_constructor: null,
      win_toString: null,
      win_is_collection: false,

      // Chain probing (property X.Y for various Y)
      chain: {},
    };

    // --- Document-level ---
    try {
      const dv = doc[name];
      r.doc_type = typeof dv;

      if (dv != null && dv !== undefined) {
        r.doc_constructor = dv.constructor?.name || null;
        try { r.doc_toString = String(dv).substring(0, 500); } catch(e) { r.doc_toString = '[toString_error]'; }

        r.doc_is_collection = (dv instanceof win.HTMLCollection) || (dv instanceof win.NodeList);
        if (r.doc_is_collection) {
          r.doc_collection_length = dv.length;
        }

        // Prototype chain (max 5)
        let p = dv;
        for (let j = 0; j < 5 && p; j++) {
          const proto = Object.getPrototypeOf(p);
          if (proto && proto.constructor) {
            r.doc_proto_chain.push(proto.constructor.name);
          }
          p = proto;
        }

        // Chain property probing
        probeChain(dv, win, r.chain);
      }
    } catch(e) {
      r.doc_type = 'error';
      r.doc_toString = e.message?.substring(0, 200);
    }

    // --- Window-level ---
    try {
      const wv = win[name];
      r.win_type = typeof wv;
      if (wv != null && wv !== undefined) {
        r.win_constructor = wv.constructor?.name || null;
        try { r.win_toString = String(wv).substring(0, 500); } catch(e) { r.win_toString = '[toString_error]'; }
        r.win_is_collection = (wv instanceof win.HTMLCollection) || (wv instanceof win.NodeList);
      }
    } catch(e) {
      r.win_type = 'error';
      r.win_toString = e.message?.substring(0, 200);
    }

    return r;
  }

  function probeChain(obj, win, chain) {
    const CHAIN_PROPS = [
      'src', 'href', 'action', 'data', 'value', 'name', 'id', 'type',
      'method', 'target', 'className', 'innerHTML', 'textContent',
      'hostname', 'protocol', 'pathname', 'port', 'search', 'hash',
      'toString', 'valueOf', 'length',
    ];

    for (const cp of CHAIN_PROPS) {
      try {
        const cv = obj[cp];
        if (cv !== undefined) {
          chain[cp] = {
            type: typeof cv,
            constructor: (cv != null && cv.constructor) ? cv.constructor.name : null,
            value: typeof cv === 'function'
              ? '[function]'
              : String(cv).substring(0, 200),
          };
        }
      } catch(e) {
        chain[cp] = { type: 'error', constructor: null, value: e.message?.substring(0, 100) };
      }
    }

    // valueOf/toString coercion test
    try {
      const coerced = obj + '';
      chain['_plus_empty'] = { type: 'string', constructor: 'String', value: coerced.substring(0, 500) };
    } catch(e) {
      chain['_plus_empty'] = { type: 'error', constructor: null, value: e.message?.substring(0, 100) };
    }

    // Numeric coercion
    try {
      const num = +obj;
      chain['_unary_plus'] = { type: 'number', constructor: 'Number', value: String(num) };
    } catch(e) {}

    // If it's an HTMLCollection, probe named items
    if (obj instanceof win.HTMLCollection || obj instanceof win.NodeList) {
      try {
        for (let k = 0; k < Math.min(obj.length, 5); k++) {
          const item = obj[k];
          if (item) {
            chain['_item_' + k] = {
              type: typeof item,
              constructor: item.constructor?.name || null,
              value: item.tagName?.toLowerCase() || String(item).substring(0, 100),
            };
            // Also check named access on the collection
            if (item.name && obj.namedItem) {
              try {
                const named = obj.namedItem(item.name);
                chain['_named_' + item.name] = {
                  type: typeof named,
                  constructor: named?.constructor?.name || null,
                  value: named?.tagName?.toLowerCase() || String(named).substring(0, 100),
                };
              } catch(e2) {}
            }
          }
        }
      } catch(e) {}
    }
  }
})()
