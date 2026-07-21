;; Fixture (hand-written wat): a perfectly valid wasm module that simply
;; isn't a rule — none of the required ABI exports exist. Load must fail
;; with a clear error naming the missing export.
(module
  (memory 1))
