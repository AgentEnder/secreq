// Minimal JSON support for the rule ABI — hand-rolled so it runs under the
// AssemblyScript `stub` runtime with zero dependencies. The parser is
// shape-specific: it decodes exactly the ctx object the secreq host sends
// (strings, string arrays, and an array of `{name, command}` objects) and
// skips unknown fields so a newer host can add ctx fields without breaking
// already-compiled rules. Malformed input aborts (host sees a clean trap).

import { Caller, RuleCtx } from './ctx';

/** Escape `s` as a JSON string literal, including the surrounding quotes. */
export function quoteJson(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c == 0x22) {
      out += '\\"';
    } else if (c == 0x5c) {
      out += '\\\\';
    } else if (c == 0x08) {
      out += '\\b';
    } else if (c == 0x09) {
      out += '\\t';
    } else if (c == 0x0a) {
      out += '\\n';
    } else if (c == 0x0c) {
      out += '\\f';
    } else if (c == 0x0d) {
      out += '\\r';
    } else if (c < 0x20) {
      out += '\\u' + c.toString(16).padStart(4, '0');
    } else {
      out += String.fromCharCode(c);
    }
  }
  return out + '"';
}

/** Recursive-descent parser over an already-decoded UTF-16 string. */
class Parser {
  text: string;
  pos: i32 = 0;

  constructor(text: string) {
    this.text = text;
  }

  fail(what: string): void {
    abort('secreq-rule: malformed ctx JSON: ' + what);
  }

  skipWs(): void {
    while (this.pos < this.text.length) {
      const c = this.text.charCodeAt(this.pos);
      if (c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d) {
        this.pos++;
      } else {
        break;
      }
    }
  }

  peek(): i32 {
    if (this.pos >= this.text.length) this.fail('unexpected end of input');
    return this.text.charCodeAt(this.pos);
  }

  expect(c: i32): void {
    if (this.peek() != c) {
      this.fail('expected `' + String.fromCharCode(c) + '`');
    }
    this.pos++;
  }

  parseString(): string {
    this.skipWs();
    this.expect(0x22); // `"`
    let out = '';
    while (true) {
      const c = this.peek();
      this.pos++;
      if (c == 0x22) return out;
      if (c != 0x5c) {
        // Not an escape: copy through (surrogate pairs pass unharmed as
        // two UTF-16 units).
        out += String.fromCharCode(c);
        continue;
      }
      const e = this.peek();
      this.pos++;
      if (e == 0x22) out += '"';
      else if (e == 0x5c) out += '\\';
      else if (e == 0x2f) out += '/';
      else if (e == 0x62) out += '\b';
      else if (e == 0x66) out += '\f';
      else if (e == 0x6e) out += '\n';
      else if (e == 0x72) out += '\r';
      else if (e == 0x74) out += '\t';
      else if (e == 0x75) out += String.fromCharCode(this.parseHex4());
      else this.fail('bad escape');
    }
  }

  parseHex4(): i32 {
    let v = 0;
    for (let i = 0; i < 4; i++) {
      const c = this.peek();
      this.pos++;
      let d = -1;
      if (c >= 0x30 && c <= 0x39) d = c - 0x30;
      else if (c >= 0x61 && c <= 0x66) d = c - 0x61 + 10;
      else if (c >= 0x41 && c <= 0x46) d = c - 0x41 + 10;
      else this.fail('bad \\u escape');
      v = (v << 4) | d;
    }
    return v;
  }

  parseStringArray(): string[] {
    const out: string[] = [];
    this.skipWs();
    this.expect(0x5b); // `[`
    this.skipWs();
    if (this.peek() == 0x5d) {
      this.pos++;
      return out;
    }
    while (true) {
      out.push(this.parseString());
      this.skipWs();
      const c = this.peek();
      this.pos++;
      if (c == 0x5d) return out; // `]`
      if (c != 0x2c) this.fail('expected `,` or `]`'); // `,`
    }
  }

  parseCaller(): Caller {
    const caller = new Caller();
    this.skipWs();
    this.expect(0x7b); // `{`
    this.skipWs();
    if (this.peek() == 0x7d) {
      this.pos++;
      return caller;
    }
    while (true) {
      const key = this.parseString();
      this.skipWs();
      this.expect(0x3a); // `:`
      if (key == 'name') caller.name = this.parseString();
      else if (key == 'command') caller.command = this.parseString();
      else this.skipValue();
      this.skipWs();
      const c = this.peek();
      this.pos++;
      if (c == 0x7d) return caller; // `}`
      if (c != 0x2c) this.fail('expected `,` or `}`');
    }
  }

  parseCallers(): Caller[] {
    const out: Caller[] = [];
    this.skipWs();
    this.expect(0x5b); // `[`
    this.skipWs();
    if (this.peek() == 0x5d) {
      this.pos++;
      return out;
    }
    while (true) {
      out.push(this.parseCaller());
      this.skipWs();
      const c = this.peek();
      this.pos++;
      if (c == 0x5d) return out;
      if (c != 0x2c) this.fail('expected `,` or `]`');
    }
  }

  /** Skip any JSON value — future-proofing for ctx fields we don't know. */
  skipValue(): void {
    this.skipWs();
    const c = this.peek();
    if (c == 0x22) {
      this.parseString();
    } else if (c == 0x7b) {
      // `{`
      this.pos++;
      this.skipWs();
      if (this.peek() == 0x7d) {
        this.pos++;
        return;
      }
      while (true) {
        this.parseString();
        this.skipWs();
        this.expect(0x3a);
        this.skipValue();
        this.skipWs();
        const d = this.peek();
        this.pos++;
        if (d == 0x7d) return;
        if (d != 0x2c) this.fail('expected `,` or `}`');
      }
    } else if (c == 0x5b) {
      // `[`
      this.pos++;
      this.skipWs();
      if (this.peek() == 0x5d) {
        this.pos++;
        return;
      }
      while (true) {
        this.skipValue();
        this.skipWs();
        const d = this.peek();
        this.pos++;
        if (d == 0x5d) return;
        if (d != 0x2c) this.fail('expected `,` or `]`');
      }
    } else {
      // Number / true / false / null: consume the literal run.
      while (this.pos < this.text.length) {
        const d = this.text.charCodeAt(this.pos);
        if (
          d == 0x2c || // `,`
          d == 0x5d || // `]`
          d == 0x7d || // `}`
          d == 0x20 ||
          d == 0x09 ||
          d == 0x0a ||
          d == 0x0d
        ) {
          break;
        }
        this.pos++;
      }
    }
  }
}

/** Parse the host's ctx JSON into a `RuleCtx`. Aborts on malformed input. */
export function parseRuleCtx(text: string): RuleCtx {
  const p = new Parser(text);
  const ctx = new RuleCtx();
  p.skipWs();
  p.expect(0x7b); // `{`
  p.skipWs();
  if (p.peek() == 0x7d) {
    p.pos++;
    return ctx;
  }
  while (true) {
    const key = p.parseString();
    p.skipWs();
    p.expect(0x3a); // `:`
    if (key == 'wrap') ctx.wrap = p.parseString();
    else if (key == 'joined_argv') ctx.joinedArgv = p.parseString();
    else if (key == 'callers') ctx.callers = p.parseCallers();
    else if (key == 'cwd') ctx.cwd = p.parseString();
    else if (key == 'secrets') ctx.secrets = p.parseStringArray();
    else p.skipValue();
    p.skipWs();
    const c = p.peek();
    p.pos++;
    if (c == 0x7d) return ctx; // `}`
    if (c != 0x2c) p.fail('expected `,` or `}`');
  }
}
