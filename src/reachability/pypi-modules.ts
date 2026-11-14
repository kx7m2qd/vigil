import { normalizePypi } from "../engines/pkgrisk/manifests.js";

/**
 * PyPI distributions whose import name is not their (normalized) distribution name. Without
 * this, `import yaml` would not count as using PyYAML and PyYAML would look unreachable.
 * Keys are PEP 503 normalized.
 */
const KNOWN: Record<string, string[]> = {
  attrs: ["attr", "attrs"],
  beautifulsoup4: ["bs4"],
  "discord-py": ["discord"],
  djangorestframework: ["rest_framework"],
  "django-cors-headers": ["corsheaders"],
  "django-environ": ["environ"],
  "django-filter": ["django_filters"],
  dnspython: ["dns"],
  "email-validator": ["email_validator"],
  "faiss-cpu": ["faiss"],
  "faiss-gpu": ["faiss"],
  "google-api-python-client": ["googleapiclient"],
  grpcio: ["grpc"],
  "ipython": ["IPython"],
  "msgpack-python": ["msgpack"],
  mysqlclient: ["MySQLdb"],
  "opencv-contrib-python": ["cv2"],
  "opencv-python": ["cv2"],
  "opencv-python-headless": ["cv2"],
  pillow: ["PIL"],
  protobuf: ["google"],
  "psycopg2-binary": ["psycopg2"],
  "psycopg-binary": ["psycopg"],
  pycryptodome: ["Crypto"],
  pycryptodomex: ["Cryptodome"],
  pyjwt: ["jwt"],
  pymupdf: ["fitz", "pymupdf"],
  pyopenssl: ["OpenSSL"],
  pyserial: ["serial"],
  "python-dateutil": ["dateutil"],
  "python-multipart": ["multipart", "python_multipart"],
  pytz: ["pytz"],
  pywin32: ["win32api", "win32con", "win32com", "pywintypes", "win32file", "win32event"],
  pyyaml: ["yaml"],
  pyzmq: ["zmq"],
  "ruamel-yaml": ["ruamel"],
  "scikit-image": ["skimage"],
  "scikit-learn": ["sklearn"],
  setuptools: ["setuptools", "pkg_resources"],
  "typing-extensions": ["typing_extensions"],
  "websocket-client": ["websocket"],
};

/**
 * Every top-level module name this distribution plausibly provides. Over-inclusive on purpose:
 * an extra candidate can only turn "unreachable" into "reachable", never the reverse.
 */
export function moduleCandidates(dist: string): string[] {
  const n = normalizePypi(dist);
  const out = new Set<string>([n.replace(/-/g, "_"), ...(KNOWN[n] ?? [])]);
  // google-cloud-storage → google, azure-storage-blob → azure, zope-interface → zope
  const ns = /^(google|azure|zope|jaraco|backports|sphinxcontrib)-/.exec(n);
  if (ns) out.add(ns[1] as string);
  const stripped = n
    .replace(/^python-/, "")
    .replace(/^py(?=[a-z]{3,})/, "")
    .replace(/-(binary|headless|cpu|gpu|slim|lite)$/, "");
  out.add(stripped.replace(/-/g, "_"));
  if (n.startsWith("py")) out.add(n.replace(/^py-?/, "").replace(/-/g, "_"));
  return [...out].filter(Boolean);
}

/** Module names known for certain (no guessing): safe to look for in free text like CI config. */
export function exactModules(dist: string): string[] {
  const n = normalizePypi(dist);
  return [...new Set([n.replace(/-/g, "_"), ...(KNOWN[n] ?? [])])];
}
