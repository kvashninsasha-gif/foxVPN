import {defineConfig} from 'vitest/config';
export default defineConfig({test:{environment:'jsdom',maxWorkers:2,testTimeout:10000,setupFiles:['tests/setup.ts'],include:['tests/**/*.test.tsx']}});
