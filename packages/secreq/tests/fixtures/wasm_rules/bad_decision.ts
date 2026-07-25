// Fixture (raw ABI, compiled with --raw): implements the wasm ABI by hand
// but returns decision JSON the host doesn't recognize. Proves the host
// rejects malformed decisions cleanly instead of panicking.

export function alloc(len: i32): usize {
  return heap.alloc(len);
}

export function decide(ptr: usize, len: i32): u64 {
  const buf = String.UTF8.encode('{"maybe":"perhaps"}');
  const out = changetype<usize>(buf);
  return ((out as u64) << 32) | ((buf.byteLength as u64) & 0xffffffff);
}
