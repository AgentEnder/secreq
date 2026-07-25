/**
 * Registers `<secreq-shot>`, in the browser only.
 *
 * Split from the implementation for the same reason as
 * `secreq-terminal.ts`: `class … extends HTMLElement` runs the moment a
 * module loads, and this site pre-renders every page in Node where
 * `HTMLElement` does not exist. A dynamic import keeps the class off the
 * server entirely.
 */
if (typeof window !== 'undefined') {
  void import('./secreq-shot-element');
}

export {};
