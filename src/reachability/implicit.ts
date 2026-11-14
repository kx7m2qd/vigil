/**
 * Packages that a library loads by name at runtime, so the project never imports them itself:
 * database drivers picked by a connection URL, template engines picked by file extension, optional
 * accelerators. If the loader is in use, an unimported package from its list gets "unknown", never
 * "unreachable". The lists are deliberately broad; a missing entry is the only way this file can
 * cause a wrong verdict.
 */
import { normalizePypi } from "../engines/pkgrisk/manifests.js";

const NPM: Record<string, string[]> = {
  sequelize: ["pg", "pg-hstore", "mysql2", "mariadb", "sqlite3", "tedious", "oracledb", "ibm_db"],
  knex: ["pg", "pg-native", "mysql", "mysql2", "sqlite3", "better-sqlite3", "tedious", "oracledb"],
  typeorm: ["pg", "mysql", "mysql2", "mariadb", "sqlite3", "better-sqlite3", "mssql", "oracledb", "mongodb", "sql.js", "redis", "ioredis"],
  "@mikro-orm/core": ["pg", "mysql2", "mariadb", "sqlite3", "better-sqlite3", "mongodb"],
  objection: ["knex", "pg", "mysql", "mysql2", "sqlite3"],
  bookshelf: ["knex", "pg", "mysql", "mysql2", "sqlite3"],
  "@prisma/client": ["prisma", "@prisma/engines"],
  express: ["pug", "jade", "ejs", "hbs", "handlebars", "express-handlebars", "nunjucks", "mustache", "twig", "eta", "liquidjs", "consolidate"],
  koa: ["koa-views"],
  "koa-views": ["pug", "ejs", "handlebars", "nunjucks", "consolidate"],
  consolidate: ["pug", "jade", "ejs", "handlebars", "nunjucks", "mustache", "twig", "eta", "liquidjs", "swig", "dot", "underscore", "lodash"],
  fastify: ["pino-pretty"],
  pino: ["pino-pretty", "thread-stream"],
  winston: ["winston-transport"],
  next: ["sharp", "react", "react-dom", "styled-jsx", "@next/env", "critters", "postcss"],
  nuxt: ["vue", "vue-router", "sharp"],
  ws: ["bufferutil", "utf-8-validate"],
  "socket.io": ["bufferutil", "utf-8-validate", "ws"],
  mongoose: ["mongodb", "kerberos", "snappy", "@mongodb-js/zstd", "mongodb-client-encryption"],
  nodemailer: ["aws-sdk", "@aws-sdk/client-ses"],
  bull: ["ioredis"],
  bullmq: ["ioredis"],
  "connect-redis": ["redis", "ioredis"],
  passport: ["passport-local", "passport-jwt", "passport-google-oauth20", "passport-github2", "passport-facebook"],
  "node-fetch": ["encoding"],
  axios: ["follow-redirects", "form-data", "proxy-from-env"],
};

const PYPI: Record<string, string[]> = {
  sqlalchemy: ["psycopg2", "psycopg2-binary", "psycopg", "psycopg-binary", "pymysql", "mysqlclient", "mysql-connector-python", "asyncpg", "aiosqlite", "aiomysql", "cx-oracle", "oracledb", "pyodbc", "pymssql", "snowflake-sqlalchemy", "sqlalchemy-utils"],
  "flask-sqlalchemy": ["sqlalchemy", "psycopg2", "psycopg2-binary", "psycopg", "pymysql", "mysqlclient"],
  django: ["psycopg2", "psycopg2-binary", "psycopg", "psycopg-binary", "mysqlclient", "pymysql", "cx-oracle", "oracledb", "redis", "django-redis", "pylibmc", "pymemcache", "argon2-cffi", "bcrypt", "pillow", "jinja2", "whitenoise", "gunicorn", "uvicorn"],
  celery: ["redis", "amqp", "librabbitmq", "kombu", "eventlet", "gevent", "sqlalchemy", "pymongo", "boto3", "pycurl"],
  kombu: ["redis", "amqp", "librabbitmq", "boto3", "pycurl"],
  pandas: ["openpyxl", "xlrd", "xlsxwriter", "pyarrow", "fastparquet", "lxml", "html5lib", "beautifulsoup4", "sqlalchemy", "odfpy", "tables", "pyxlsb", "fsspec", "s3fs", "gcsfs", "numexpr", "bottleneck", "tabulate", "matplotlib", "jinja2"],
  uvicorn: ["uvloop", "httptools", "websockets", "wsproto", "watchfiles", "python-dotenv", "pyyaml"],
  gunicorn: ["gevent", "eventlet", "tornado", "uvicorn", "setproctitle", "greenlet"],
  starlette: ["python-multipart", "jinja2", "itsdangerous", "httpx", "pyyaml"],
  fastapi: ["python-multipart", "jinja2", "itsdangerous", "httpx", "pyyaml", "email-validator", "ujson", "orjson", "uvicorn"],
  flask: ["python-dotenv", "watchdog", "asgiref", "cryptography"],
  requests: ["pysocks", "chardet", "charset-normalizer", "brotli", "brotlicffi", "cryptography", "pyopenssl"],
  httpx: ["h2", "brotli", "brotlicffi", "socksio", "zstandard"],
  aiohttp: ["aiodns", "brotli", "cchardet", "charset-normalizer"],
  urllib3: ["pysocks", "brotli", "brotlicffi", "zstandard", "h2"],
  jinja2: ["markupsafe", "babel"],
  pydantic: ["email-validator", "python-dotenv"],
  "pydantic-settings": ["python-dotenv", "pyyaml"],
  boto3: ["awscrt"],
  scrapy: ["pyopenssl", "cryptography", "brotli", "zstandard"],
  transformers: ["torch", "tensorflow", "safetensors", "tokenizers", "sentencepiece", "accelerate", "protobuf"],
  "python-jose": ["cryptography", "pycryptodome", "rsa", "ecdsa"],
  pyjwt: ["cryptography"],
  paramiko: ["cryptography", "bcrypt", "pynacl", "gssapi"],
  matplotlib: ["pillow", "pyqt5", "pyside6", "tk"],
};

export function npmLoaders(): Record<string, string[]> {
  return NPM;
}

/** Loaders keyed by normalized PyPI name, loaded packages normalized too. */
export function pypiLoaders(): Record<string, string[]> {
  return Object.fromEntries(Object.entries(PYPI).map(([k, v]) => [normalizePypi(k), v.map(normalizePypi)]));
}
