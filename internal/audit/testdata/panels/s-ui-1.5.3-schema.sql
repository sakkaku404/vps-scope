-- S-UI 1.5.3 schema surface used by VPS Scope.
-- This fixture contains table definitions only; it has no panel settings,
-- users, tokens, endpoints, certificates, private keys, or other runtime data.
CREATE TABLE `settings` (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  `key` text,
  `value` text
);

CREATE TABLE `tls` (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  `name` text,
  `server` blob,
  `client` blob
);

CREATE TABLE `inbounds` (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  `type` text,
  `tag` text,
  `tls_id` integer,
  `addrs` blob,
  `out_json` blob,
  `options` blob,
  CONSTRAINT `fk_inbounds_tls` FOREIGN KEY (`tls_id`) REFERENCES `tls`(`id`),
  CONSTRAINT `uni_inbounds_tag` UNIQUE (`tag`)
);
