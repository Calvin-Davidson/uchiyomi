// The languages a script source can be written in (engine.ts). One entry per language, each in its own file.
import type { ScriptRunner } from './engine';
import { javascript } from './javascript';

export const RUNNERS: ScriptRunner[] = [javascript];
