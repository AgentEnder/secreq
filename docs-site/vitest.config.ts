import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['components/ui/**/*.test.ts', 'components/ui/**/*.test.tsx'],
  },
});
