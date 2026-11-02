// Python script sources (`.py`): run with `python3` (`python` on Windows), or SCRIPT_PYTHON.
import type { ScriptRunner } from './engine';

export const python: ScriptRunner = {
  name: 'Python',
  exts: ['.py'],
  command: (file, args) => ({
    cmd: process.env.SCRIPT_PYTHON || (process.platform === 'win32' ? 'python' : 'python3'),
    // -u: unbuffered, so a killed script still leaves what it printed; UTF-8 whatever the host's locale.
    args: ['-u', file, ...args],
    env: { PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1', PYTHONDONTWRITEBYTECODE: '1' },
  }),
};
