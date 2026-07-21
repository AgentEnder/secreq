;; Fixture (hand-written wat): instantiates fine, but `decide` claims a
;; decision of 65537 bytes (ptr 0, len = MAX_DECISION_LEN + 1). The host
;; must reject the oversized length before attempting to read it.
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    i32.const 8)
  (func (export "decide") (param i32 i32) (result i64)
    i64.const 65537))
