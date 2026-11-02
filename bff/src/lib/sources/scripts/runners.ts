// The languages a script source can be written in (engine.ts). One entry per language, each in its own file.
import type { ScriptRunner } from './engine';
import { python } from './python';

export const RUNNERS: ScriptRunner[] = [python];
