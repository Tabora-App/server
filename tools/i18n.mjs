// Translation dictionaries for server messages and e-mails.
//
// The server's source language is Russian: every user-facing string in src/*.rs is written in
// Russian and looked up in i18n/<lang>.json ("Russian text" -> translation) at run time, see
// src/i18n.rs. This tool keeps the dictionaries in step with the code.
//
//   node tools/i18n.mjs check              what is missing in i18n/<lang>.json
//   node tools/i18n.mjs check --strict     exit 1 if anything is missing or a translation is broken
//   node tools/i18n.mjs check --todo       write the missing strings to .build/i18n-todo.json
//   node tools/i18n.mjs merge <lang> <file.json>... [--replace]
//                                          accept ready translations: { "Russian text": "translation" }
//   node tools/i18n.mjs prune [--check]    drop strings that no longer occur in the code
//
// A translation is broken when its set of placeholders ({0}, {1}...) differs from the source.
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LANGS = ["en", "uk", "es"];
const FORMS = { en: 2, es: 2, uk: 3 }; // plural forms in "one|few|many"-style strings
const CYR = /[\u0410-\u042f\u0430-\u044f\u0401\u0451]/;

function listFiles(dir, ext) {
  const out = [];
  for (const f of readdirSync(dir).sort()) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) {
      out.push(...listFiles(p, ext));
    } else if (f.endsWith(ext)) {
      out.push(p);
    }
  }
  return out;
}

/** Messages in a Rust source file: string literals with Russian text, except logging (eprintln!,
 *  panic!, expect...), the database schema (raw strings) and tests. format! placeholders ("{}",
 *  "{name}") are recorded as {0}, {1}...: the server finds the translation of a finished text by
 *  such patterns. Returns Map "message -> where it occurs". */
function rustKeysOf(file) {
  const src = readFileSync(file, "utf8");
  const keys = new Map();
  const SKIP = new Set(["eprintln!", "println!", "print!", "eprint!", "panic!", "unreachable!", "assert!", "assert_eq!", "assert_ne!", "debug_assert!", "expect", "unimplemented!", "todo!"]);
  const stack = [];
  let i = 0;
  let lineNo = 1;
  const end = src.indexOf("#[cfg(test)]");
  const stop = end < 0 ? src.length : end;
  while (i < stop) {
    const ch = src[i];
    if (ch === "\n") {
      lineNo++;
      i++;
    } else if (src.startsWith("//", i)) {
      while (i < stop && src[i] !== "\n") i++;
    } else if (src.startsWith("/*", i)) {
      const j = src.indexOf("*/", i + 2);
      const to = j < 0 ? stop : j + 2;
      lineNo += src.slice(i, to).split("\n").length - 1;
      i = to;
    } else if (ch === "r" && /^r#*"/.test(src.slice(i, i + 8)) && !/[A-Za-z0-9_]/.test(src[i - 1] || "")) {
      const hashes = /^r(#*)"/.exec(src.slice(i, i + 8))[1];
      const j = src.indexOf(`"${hashes}`, i + 2 + hashes.length);
      const to = j < 0 ? stop : j + 1 + hashes.length;
      lineNo += src.slice(i, to).split("\n").length - 1;
      i = to; // raw strings hold the database schema and the like, not messages
    } else if (ch === "'") {
      const m = /^'(\\.|\\u\{[0-9a-fA-F]+\}|[^\\'])'/.exec(src.slice(i, i + 12));
      i += m ? m[0].length : 1;
    } else if (ch === '"') {
      const startLine = lineNo;
      let j = i + 1;
      let out = "";
      while (j < src.length && src[j] !== '"') {
        if (src[j] === "\\") {
          const n = src[j + 1];
          if (n === "n") out += "\n";
          else if (n === "t") out += "\t";
          else if (n === "r") out += "\r";
          else if (n === "0") out += "\0";
          else if (n === "u") {
            const m = /^\{([0-9a-fA-F]+)\}/.exec(src.slice(j + 2, j + 12));
            out += m ? String.fromCodePoint(parseInt(m[1], 16)) : "";
            j += m ? m[0].length : 0;
          } else if (n === "\n") {
            lineNo++;
            j += 2;
            while (/\s/.test(src[j])) {
              if (src[j] === "\n") lineNo++;
              j++;
            }
            continue; // a line continuation inside a literal: leading whitespace of the next line is dropped
          } else out += n;
          j += 2;
        } else {
          if (src[j] === "\n") lineNo++;
          out += src[j++];
        }
      }
      i = j + 1;
      if (CYR.test(out) && !stack.some(n => SKIP.has(n))) {
        let slot = 0;
        let key = "";
        for (let k = 0; k < out.length; k++) {
          if (out.startsWith("{{", k)) {
            key += "{";
            k++;
          } else if (out.startsWith("}}", k)) {
            key += "}";
            k++;
          } else if (out[k] === "{") {
            const close = out.indexOf("}", k);
            if (close < 0) {
              key += out[k];
            } else {
              key += `{${slot++}}`;
              k = close;
            }
          } else {
            key += out[k];
          }
        }
        if (!keys.has(key)) {
          keys.set(key, `${file.replace(ROOT + "/", "")}:${startLine}`);
        }
      }
    } else if (ch === "(") {
      const m = /([A-Za-z_][A-Za-z0-9_]*!?)\s*$/.exec(src.slice(Math.max(0, i - 40), i));
      stack.push(m ? m[1] : "");
      i++;
    } else if (ch === ")") {
      stack.pop();
      i++;
    } else {
      i++;
    }
  }
  return keys;
}

function serverKeys() {
  const keys = new Map();
  for (const f of listFiles(join(ROOT, "src"), ".rs")) {
    rustKeysOf(f).forEach((where, key) => keys.has(key) || keys.set(key, where));
  }
  return keys;
}

const file = lang => join(ROOT, "i18n", `${lang}.json`);
const read = lang => (existsSync(file(lang)) ? JSON.parse(readFileSync(file(lang), "utf8")) : {});
const write = (lang, dict) => writeFileSync(file(lang), JSON.stringify(dict, null, 1) + "\n");
const slots = s => [...String(s).matchAll(/\{(\d+)\}/g)].map(m => m[1]).sort().join(",");
const isForms = key => /^[^|]+\|[^|]+\|[^|]+$/.test(key) && !/\s\|\s/.test(key);

const [command, ...rest] = process.argv.slice(2);
const flags = rest.filter(a => a.startsWith("--"));
const args = rest.filter(a => !a.startsWith("--"));

if (command === "check") {
  const keys = serverKeys();
  console.log(`messages: ${keys.size}`);
  let bad = 0;
  const missingAll = new Set();
  for (const lang of LANGS) {
    const dict = read(lang);
    const missing = [...keys.keys()].filter(k => typeof dict[k] !== "string" || dict[k] === "");
    const broken = [...keys.keys()].filter(k => typeof dict[k] === "string" && dict[k] && slots(k) !== slots(dict[k]));
    console.log(`  ${lang}: translated ${keys.size - missing.length}, missing ${missing.length}${broken.length ? `, broken ${broken.length}` : ""}`);
    broken.slice(0, 10).forEach(k => console.log(`      placeholders differ: ${JSON.stringify(k).slice(0, 90)}`));
    missing.forEach(k => missingAll.add(k));
    bad += missing.length + broken.length;
  }
  if (flags.includes("--todo")) {
    mkdirSync(join(ROOT, ".build"), { recursive: true });
    const all = [...missingAll];
    writeFileSync(join(ROOT, ".build/i18n-todo.json"), JSON.stringify({ keys: all, where: Object.fromEntries(all.map(k => [k, keys.get(k)])) }, null, 1) + "\n");
    console.log(`missing strings written to .build/i18n-todo.json (${all.length})`);
  }
  process.exit(flags.includes("--strict") && bad ? 1 : 0);
} else if (command === "merge" && LANGS.includes(args[0]) && args.length > 1) {
  const [lang, ...files] = args;
  const dict = read(lang);
  const replace = flags.includes("--replace");
  let added = 0;
  let kept = 0;
  const bad = [];
  for (const f of files) {
    for (const [key, value] of Object.entries(JSON.parse(readFileSync(f, "utf8")))) {
      if (typeof value !== "string" || !value) {
        bad.push([key, "empty translation"]);
      } else if (slots(key) !== slots(value)) {
        bad.push([key, `placeholders: ${slots(key) || "none"} -> ${slots(value) || "none"}`]);
      } else if (isForms(key) && value.split("|").length !== FORMS[lang]) {
        bad.push([key, `${value.split("|").length} plural forms, ${FORMS[lang]} expected`]);
      } else if (dict[key] !== undefined && dict[key] !== value && !replace) {
        kept++;
      } else {
        dict[key] === undefined && added++;
        dict[key] = value;
      }
    }
  }
  write(lang, dict);
  console.log(`${lang}: added ${added}, kept existing ${kept}, rejected ${bad.length}`);
  bad.slice(0, 30).forEach(([key, why]) => console.log(`  ${why}: ${JSON.stringify(key).slice(0, 90)}`));
  process.exit(bad.length ? 1 : 0);
} else if (command === "prune") {
  const used = new Set(serverKeys().keys());
  let extra = 0;
  for (const lang of LANGS) {
    const dict = read(lang);
    const gone = Object.keys(dict).filter(k => !used.has(k));
    extra += gone.length;
    console.log(`${lang}: unused ${gone.length}`);
    if (gone.length && !flags.includes("--check")) {
      gone.forEach(k => delete dict[k]);
      write(lang, dict);
    }
  }
  process.exit(flags.includes("--check") && extra ? 1 : 0);
} else {
  console.error("usage: node tools/i18n.mjs check [--strict] [--todo] | merge <en|uk|es> <file.json>... [--replace] | prune [--check]");
  process.exit(2);
}
