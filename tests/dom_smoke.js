// Runs the script of a rendered report against a minimal DOM stub and prints what the page offers to copy.
// Usage: node dom_smoke.js <report.html>   (used by test_render.py; no dependencies)
'use strict';
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync(process.argv[2], 'utf8');
const scripts = Array.from(html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g));
const copied = [];

class Node {
  constructor(tag) {
    this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this._text = '';
    this.hidden = false; this.disabled = false; this.className = ''; this.title = ''; this.style = {};
    this.classList = {
      toggle: (name, on) => {
        const set = new Set(this.className.split(' ').filter(Boolean));
        if (on) set.add(name); else set.delete(name);
        this.className = Array.from(set).join(' ');
      },
      contains: (name) => this.className.split(' ').includes(name),
    };
  }
  get childNodes() { return this.children; }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  set textContent(value) { this.children = []; this._text = String(value); }
  appendChild(child) { this.children.push(child); return child; }
  removeChild(child) { this.children = this.children.filter((c) => c !== child); return child; }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  getAttribute(name) { return this.attrs[name]; }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  querySelector(selector) { return this.descendants().find((n) => n.className.split(' ').includes(selector.slice(1))) || null; }
  descendants() { return this.children.flatMap((c) => [c, ...c.descendants()]); }
  focus() {} select() {} scrollIntoView() {}
}

const registry = {};
Array.from(html.matchAll(/\sid="([^"]+)"/g)).forEach((m) => { registry[m[1]] = new Node('el'); });
registry.data._text = scripts[0][2];
const document = {
  getElementById: (id) => registry[id] || (registry[id] = new Node('el')),  // ids the script creates itself get a blank node
  createElement: (tag) => new Node(tag),
  createTextNode: (text) => { const n = new Node('#text'); n._text = String(text); return n; },
  createDocumentFragment: () => new Node('#fragment'),
  body: new Node('body'), activeElement: null, title: '', execCommand: () => false,
};
const navigator = { clipboard: { writeText: (text) => { copied.push(text); return Promise.resolve(); } } };

// optional localStorage seed: DOM_LOCAL_STORAGE='{"key": "value"}' (without it the page sees no storage at all)
const seed = process.env.DOM_LOCAL_STORAGE;
const store = seed ? JSON.parse(seed) : {};
const localStorage = seed ? { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } } : undefined;

vm.runInNewContext(scripts[1][2], { document, navigator, localStorage, setTimeout: () => 0, console });

async function click(button) {
  const before = copied.length;
  (button.listeners.click || []).forEach((fn) => fn({}));
  for (let i = 0; i < 5; i++) await Promise.resolve();
  return copied.length > before ? copied[copied.length - 1] : null;
}

(async () => {
  const bulk = [];
  for (const button of registry['bulk-body'].descendants().filter((n) => n.tag === 'button')) {
    bulk.push({ label: button.textContent, disabled: button.disabled, text: button.disabled ? null : await click(button) });
  }
  const cards = registry.cards.descendants().filter((n) => n.tag === 'article').map((card) => {
    const buttons = card.descendants().filter((n) => n.tag === 'button' && n.attrs['aria-label']);
    return { id: card.attrs.id, copyAll: buttons.some((b) => b.textContent === 'Copy all'),
             copyButtons: buttons.filter((b) => b.textContent === 'Copy').length };
  });
  const stale = document.getElementById('stale-warning');
  const verdict = registry.verdict;
  console.log(JSON.stringify({ bulk, cards, stale: { hidden: stale.hidden, text: stale.textContent },
                               verdict: { hidden: verdict.hidden, cls: verdict.className, text: verdict.textContent },
                               toolFilter: registry['f-tool'] ? registry['f-tool'].value : null,
                               statusFilter: registry['f-status'] ? registry['f-status'].value : null, storage: store,
                               summary: registry['summary-body'].textContent, cardsText: registry.cards.textContent,
                               coverage: registry['coverage-body'].textContent, bulkText: registry['bulk-body'].textContent,
                               verification: registry.verification.hidden ? '' : registry['verification-body'].textContent,
                               planned: registry.cards.descendants().filter((n) => n.className === 'alert').map((n) => n.textContent) }));
})();
