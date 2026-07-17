;; Fixture (hand-written wat): ABI-shaped, but declares a linear-memory
;; minimum of 1200 pages (~75 MiB) — above the sandbox's 64 MiB cap. The
;; registration-time smoke instantiation must reject it via the store
;; limiter instead of deferring the failure to the first ask.
(module
  (memory (export "memory") 1200)
  (func (export "alloc") (param i32) (result i32)
    i32.const 8)
  (func (export "decide") (param i32 i32) (result i64)
    i64.const 0))
