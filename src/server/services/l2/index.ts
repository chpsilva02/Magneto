/**
 * l2/index.ts — public API of the L2 module
 *
 * Consumers import from here instead of from individual files,
 * so internal refactors don't break callers.
 */

export * from './l2.types.ts';
export * from './stp-normalizer.ts';
