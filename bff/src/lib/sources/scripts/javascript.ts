// JavaScript script sources (`.js`, `.mjs`): run with the Node that runs the server (so nothing to install), or
// SCRIPT_NODE. They sit in the scripts folder, never next to the pack's compiled plugins, which are require()'d.
import type { ScriptRunner } from './engine';

export const javascript: ScriptRunner = {
  name: 'JavaScript',
  exts: ['.js', '.mjs'],
  command: (file, args) => ({
    cmd: process.env.SCRIPT_NODE || process.execPath,
    args: [file, ...args],
    // The desktop app's process.execPath is Electron, which acts as plain Node only when told to.
    env: { ELECTRON_RUN_AS_NODE: '1' },
  }),
};
