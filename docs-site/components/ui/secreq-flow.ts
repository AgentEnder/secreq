/**
 * Registers `<secreq-flow>`, in the browser only.
 *
 * Same shape, and for the same reason, as `secreq-terminal.ts` and
 * `secreq-window.ts`: `class … extends HTMLElement` is evaluated the moment
 * a module loads, and this site pre-renders every page in Node, where
 * `HTMLElement` does not exist. Guarding the `customElements.define()` call
 * is not enough — the class declaration itself must never run on the server,
 * which takes a dynamic `import()` rather than a static one.
 *
 * Importing this module is the entire integration.
 */
if (typeof window !== 'undefined') {
  void import('./secreq-flow-element');
}

export {};
