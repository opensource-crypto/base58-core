import typescript from '@rollup/plugin-typescript';

export default [
  {
    input: 'src/index.ts',
    output: { file: 'dist/index.js', format: 'esm', sourcemap: false },
    plugins: [typescript({ tsconfig: './tsconfig.json' })],
    external: ['child_process', 'fs', 'crypto', 'os'],
  },
  {
    input: 'src/index.ts',
    output: { file: 'dist/index.cjs', format: 'cjs', sourcemap: false, exports: 'named' },
    plugins: [typescript({ tsconfig: './tsconfig.json' })],
    external: ['child_process', 'fs', 'crypto', 'os'],
  },
];
