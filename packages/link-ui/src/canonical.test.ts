import { describe, expect, it } from 'vitest';

import fixtureJson from '../../secreq/src/link/canonical-v1.fixture.json?raw';

import { canonicalAskHash, verifiedAskHash } from './canonical';
import type { Ask } from './snapshot';

interface Fixture {
  contract: string;
  cases: Array<{ name: string; ask: Ask; sha256: string }>;
}

const fixture = JSON.parse(fixtureJson) as Fixture;

describe('canonical ask v1', () => {
  it('matches every shared Rust fixture', () => {
    expect(fixture.contract).toBe('secreq-link-ask-v1');
    for (const fixtureCase of fixture.cases) {
      expect(canonicalAskHash(fixtureCase.ask), fixtureCase.name).toBe(fixtureCase.sha256);
    }
  });

  it('refuses a daemon hash that does not match the rendered ask', () => {
    const fixtureCase = fixture.cases[0];
    expect(() => verifiedAskHash(fixtureCase.ask, '0'.repeat(64))).toThrow(
      'request details do not match',
    );
  });
});
