import { describe, expect, it } from 'vitest';
import { onCreateGlobalContext } from './+onCreateGlobalContext.server';

describe('onCreateGlobalContext', () => {
  it('populates docs synchronously for production prerendering', () => {
    const context: Record<string, unknown> = {};

    const result = onCreateGlobalContext(context);

    expect(result).toBeUndefined();
    expect(Object.keys(context.docs as Record<string, unknown>)).toContain('install');
    expect(context.navigation).toEqual(expect.any(Array));
  });
});
