/**
 * Registers `<secreq-terminal>`, in the browser only.
 *
 * The implementation lives in a separate module reached through a dynamic
 * `import()` rather than a static one, because `class … extends HTMLElement`
 * is evaluated the moment a module is loaded — and this site pre-renders
 * every page in Node, where `HTMLElement` does not exist. Guarding only the
 * `customElements.define()` call is not enough; the class declaration
 * itself has to never run on the server.
 *
 * Splitting it this way also keeps the element out of the server bundle
 * entirely, and leaves its implementation flat instead of nested inside a
 * `typeof window` block.
 *
 * Importing this module is the entire integration — there is no hydrate
 * function to call. `components/ui/index.ts` imports it for the sessions
 * markdown injects as raw HTML; `Term.tsx` imports it for its own.
 */
if (typeof window !== 'undefined') {
  void import('./secreq-terminal-element');
}

export {};
