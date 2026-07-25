;; Fixture (hand-written wat, parsed at test time via the `wat` dev-dep):
;; a module that implements the rule ABI but ALSO imports a WASI function.
;; The sandbox must refuse to load it — only `env.abort` may be imported.
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32)
    i32.const 16)
  (func (export "decide") (param i32 i32) (result i64)
    i64.const 0))
