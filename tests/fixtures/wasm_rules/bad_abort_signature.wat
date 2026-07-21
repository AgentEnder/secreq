;; Fixture (hand-written wat): ABI-shaped exports, but imports `env.abort`
;; with the wrong signature (param i64 instead of AssemblyScript's
;; (i32, i32, i32, i32)). Static import vetting accepts any `env.abort`
;; func; the registration-time smoke instantiation must catch the mismatch.
(module
  (import "env" "abort" (func $abort (param i64)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    i32.const 8)
  (func (export "decide") (param i32 i32) (result i64)
    i64.const 0))
