import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        include: ['tests/benchmark/**/*.test.ts'],
        testTimeout: 30000,
    },
});
