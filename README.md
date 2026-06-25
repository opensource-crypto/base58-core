
![npm](https://img.shields.io/npm/v/base58-core)
![npm downloads](https://img.shields.io/npm/dm/base58-core)
![license](https://img.shields.io/npm/l/base58-core)
![bundle size](https://img.shields.io/bundlephobia/min/base58-core)

# @base58/core

Fast, tree-shakeable Base58 encoding with TypeScript support. Zero dependencies.

## Features

- Base58 encode/decode (Bitcoin alphabet)
- Base58Check with double SHA-256 verification
- ESM + CommonJS dual build
- Full TypeScript types included
- Compatible with Bitcoin, Solana, IPFS

## CLI Tool

For command-line usage: [base58-cli](https://www.npmjs.com/package/base58-cli)

## Install

npm install @base58/core

## Usage

import { encode, decode } from "@base58/core";
const enc = encode(new Uint8Array([72, 101, 108, 108, 111]));
console.log(enc);

## License

MIT
