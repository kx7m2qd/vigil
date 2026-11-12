import { execFileSync, execSync } from 'child_process';
import * as cp from 'node:child_process';

function gitMergeBase(input: { base: string; head: string }) {
  // ruleid: js-shell-formatted-command
  return execSync(`git merge-base ${input.head} ${input.base}`).toString().trim();
}

function checkInterfaces(file: string) {
  const cmd = `cat ${file} 2> /dev/null | grep 'iface\\|source'`;
  // ruleid: js-shell-formatted-command
  return execSync(cmd).toString().split('\n');
}

function remove(dir: string, done: () => void) {
  // ruleid: js-shell-formatted-command
  cp.exec('rm -rf ' + dir, done);
}

function gitMergeBaseSafe(input: { base: string; head: string }) {
  // ok: js-shell-formatted-command
  return execFileSync('git', ['merge-base', input.head, input.base]).toString().trim();
}

function uptime() {
  // ok: js-shell-formatted-command
  return execSync('uptime').toString();
}

function removeSafe(dir: string) {
  // ok: js-shell-formatted-command
  cp.execFile('rm', ['-rf', '--', dir], () => {});
}
