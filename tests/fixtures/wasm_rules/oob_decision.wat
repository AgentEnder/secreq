;; Fixture (hand-written wat): honors the ABI shape but `decide` returns a
;; packed pointer far outside linear memory (ptr = 0x7fff0000, len = 16).
;; The host must reject the out-of-bounds read cleanly.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    i32.const 8)
  (func (export "decide") (param i32 i32) (result i64)
    i64.const 0x7fff0000_00000010))
