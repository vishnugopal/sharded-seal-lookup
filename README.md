# sharded-seal-lookup

Sharded Seal Lookup aims to help folks learn how to implement [private information retrieval](https://en.wikipedia.org/wiki/Private_information_retrieval) using [homomorphic encryption](https://en.wikipedia.org/wiki/Homomorphic_encryption). None of this code should be used in production, but it should be a good starting point for learning about the topic.

## Getting Started

1. First install [bun](https://bun.sh/), a fast batteries-included runtime for JavaScript and TypeScript.
2. Run `bun install` to install the dependencies.
3. Now `EXPLAIN=1 bun run test.ts` should get you started.
4. `test-values.ts` is the same as `test.ts` but with values instead of just the presence of mobile numbers.

For more detailed explanations, you can increase the explain parameter above, i.e. `EXPLAIN=2 bun run test.ts`.

## Exploring the Code

I've tried as much as possible to make the code easy to read and understand. Start from `test.ts` and make your way through the other files.
