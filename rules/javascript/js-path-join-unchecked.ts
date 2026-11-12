import path from 'path';
import fs from 'fs';

export function resolveTemplate(basepath: string, to: string) {
  // ruleid: js-path-join-unchecked
  return path.resolve(basepath, to);
}

export function resolveChecked(basepath: string, to: string) {
  // ok: js-path-join-unchecked
  const resolved = path.resolve(basepath, to);
  if (resolved !== basepath && resolved.indexOf(basepath + path.sep) !== 0) {
    throw new Error('outside root');
  }
  return resolved;
}

export const safeStatic = (staticPath: string, requestUrl: string) => {
  const root = path.resolve(staticPath);
  // ok: js-path-join-unchecked
  const resolvedPath = path.resolve(root, requestUrl);
  const rel = path.relative(root, resolvedPath);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return;
  }
  return resolvedPath;
};

export function startsWithCheck(root: string, name: string) {
  // ok: js-path-join-unchecked
  const p = path.join(root, name);
  if (!p.startsWith(root + path.sep)) throw new Error('bad');
  return fs.readFileSync(p);
}

export function basenameSafe(root: string, name: string) {
  // ok: js-path-join-unchecked
  return fs.readFileSync(path.join(root, path.basename(name)));
}

export function writeKey(tempDir: string, key: string, data: Buffer) {
  // ruleid: js-path-join-unchecked
  const filePath = path.join(tempDir, key);
  fs.writeFileSync(filePath, data);
}

export function constantSeg(root: string) {
  // ok: js-path-join-unchecked
  return path.join(root, 'index.html');
}

const INDEX = 'index.html';

export const hasIndex = (staticPath: string) =>
  // ok: js-path-join-unchecked
  fs.existsSync(path.join(staticPath, INDEX));

export const loadPartial = (dir: string, name: string) =>
  // ruleid: js-path-join-unchecked
  fs.readFileSync(path.join(dir, name), 'utf8');

export const read = function (root: string, rel: string) {
  // ruleid: js-path-join-unchecked
  return fs.readFileSync(path.join(root, rel));
};

export const download = (req: any, res: any) => {
  // ok: js-path-join-unchecked
  const file = path.join('/srv/uploads', req.query.name);
  res.sendFile(file);
};
