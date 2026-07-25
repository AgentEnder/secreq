// as-pect configuration. `npm test` compiles every matching spec (plus the
// rule it imports) to wasm and runs it — see assembly/__tests__/.
// Compiler options live in as-pect.asconfig.json.
export default {
  entries: ["assembly/__tests__/**/*.spec.ts"],
  include: ["assembly/__tests__/**/*.include.ts"],
  disclude: [/node_modules/],
  async instantiate(memory, createImports, instantiate, binary) {
    return instantiate(binary, createImports({ env: { memory } }));
  },
  outputBinary: false,
};
