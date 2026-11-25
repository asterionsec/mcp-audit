// A deliberately small TOML reader for the part of ~/.codex/config.toml that defines MCP servers:
// tables ([a.b."c d"]), key = value with basic and literal strings, numbers, booleans, arrays of those
// values (also across lines) and inline tables. Anything else on a line it does not understand is
// skipped, never guessed: the audit then simply sees less of that file.

export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;
export interface TomlTable {
  [key: string]: TomlValue;
}

export class TomlError extends Error {}

export function parseToml(text: string): TomlTable {
  const root: TomlTable = {};
  let current = root;
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  for (let index = 0; index < lines.length; index++) {
    let line = stripComment(lines[index] ?? "").trim();
    if (!line) continue;
    if (line.startsWith("[[")) {
      // Arrays of tables are not used for MCP servers; their content is ignored until the next table.
      current = {};
      continue;
    }
    if (line.startsWith("[")) {
      const end = line.lastIndexOf("]");
      if (end < 1) throw new TomlError(`line ${index + 1}: unterminated table header`);
      current = descend(root, splitKey(line.slice(1, end)));
      continue;
    }
    const equals = findEquals(line);
    if (equals < 0) continue;
    const keyPath = splitKey(line.slice(0, equals));
    let valueText = line.slice(equals + 1).trim();
    // Arrays and inline tables may span lines: keep reading until the brackets balance.
    while (!balanced(valueText) && index + 1 < lines.length) {
      index++;
      valueText += " " + stripComment(lines[index] ?? "").trim();
    }
    const parser = new ValueParser(valueText);
    const value = parser.value();
    const last = keyPath.pop();
    if (last === undefined) continue;
    descend(current, keyPath)[last] = value;
  }
  return root;
}

function descend(table: TomlTable, path: string[]): TomlTable {
  let current = table;
  for (const key of path) {
    const next = current[key];
    if (next && typeof next === "object" && !Array.isArray(next)) {
      current = next;
    } else {
      const created: TomlTable = {};
      current[key] = created;
      current = created;
    }
  }
  return current;
}

function splitKey(text: string): string[] {
  const parts: string[] = [];
  let buffer = "";
  let quote: string | null = null;
  for (let index = 0; index < text.length; index++) {
    const char = text[index] as string;
    if (quote) {
      if (char === "\\" && quote === '"') {
        buffer += text[index + 1] ?? "";
        index++;
      } else if (char === quote) {
        quote = null;
      } else {
        buffer += char;
      }
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === ".") {
      parts.push(buffer.trim());
      buffer = "";
    } else {
      buffer += char;
    }
  }
  parts.push(buffer.trim());
  return parts.filter((part) => part.length > 0);
}

function stripComment(line: string): string {
  let quote: string | null = null;
  for (let index = 0; index < line.length; index++) {
    const char = line[index];
    if (quote) {
      if (char === "\\" && quote === '"') index++;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "#") {
      return line.slice(0, index);
    }
  }
  return line;
}

function findEquals(line: string): number {
  let quote: string | null = null;
  for (let index = 0; index < line.length; index++) {
    const char = line[index];
    if (quote) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "=") {
      return index;
    }
  }
  return -1;
}

function balanced(text: string): boolean {
  let depth = 0;
  let quote: string | null = null;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (quote) {
      if (char === "\\" && quote === '"') index++;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "[" || char === "{") {
      depth++;
    } else if (char === "]" || char === "}") {
      depth--;
    }
  }
  return depth <= 0 && quote === null;
}

class ValueParser {
  private position = 0;
  constructor(private readonly text: string) {}

  value(): TomlValue {
    this.skipSpace();
    const char = this.text[this.position];
    if (char === '"') return this.basicString();
    if (char === "'") return this.literalString();
    if (char === "[") return this.array();
    if (char === "{") return this.inlineTable();
    return this.bare();
  }

  private skipSpace(): void {
    while (this.position < this.text.length && /\s/.test(this.text[this.position] as string)) this.position++;
  }

  private basicString(): string {
    if (this.text.startsWith('"""', this.position)) {
      const end = this.text.indexOf('"""', this.position + 3);
      if (end < 0) throw new TomlError("unterminated multi-line string");
      const value = this.text.slice(this.position + 3, end);
      this.position = end + 3;
      return value;
    }
    this.position++;
    let value = "";
    while (this.position < this.text.length) {
      const char = this.text[this.position] as string;
      if (char === '"') {
        this.position++;
        return value;
      }
      if (char === "\\") {
        const next = this.text[this.position + 1] ?? "";
        const escapes: Record<string, string> = { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\", b: "\b", f: "\f" };
        if (next === "u" || next === "U") {
          const length = next === "u" ? 4 : 8;
          const hex = this.text.slice(this.position + 2, this.position + 2 + length);
          value += String.fromCodePoint(Number.parseInt(hex, 16));
          this.position += 2 + length;
          continue;
        }
        value += escapes[next] ?? next;
        this.position += 2;
        continue;
      }
      value += char;
      this.position++;
    }
    throw new TomlError("unterminated string");
  }

  private literalString(): string {
    const end = this.text.indexOf("'", this.position + 1);
    if (end < 0) throw new TomlError("unterminated literal string");
    const value = this.text.slice(this.position + 1, end);
    this.position = end + 1;
    return value;
  }

  private array(): TomlValue[] {
    this.position++;
    const values: TomlValue[] = [];
    for (;;) {
      this.skipSpace();
      if (this.text[this.position] === "]") {
        this.position++;
        return values;
      }
      if (this.position >= this.text.length) throw new TomlError("unterminated array");
      values.push(this.value());
      this.skipSpace();
      if (this.text[this.position] === ",") this.position++;
    }
  }

  private inlineTable(): TomlTable {
    this.position++;
    const table: TomlTable = {};
    for (;;) {
      this.skipSpace();
      if (this.text[this.position] === "}") {
        this.position++;
        return table;
      }
      if (this.position >= this.text.length) throw new TomlError("unterminated inline table");
      const rest = this.text.slice(this.position);
      const equals = findEquals(rest);
      if (equals < 0) throw new TomlError("inline table entry without =");
      const keyPath = splitKey(rest.slice(0, equals));
      this.position += equals + 1;
      const value = this.value();
      const last = keyPath.pop();
      if (last !== undefined) descend(table, keyPath)[last] = value;
      this.skipSpace();
      if (this.text[this.position] === ",") this.position++;
    }
  }

  private bare(): TomlValue {
    const match = /^[^,\]}\s]+/.exec(this.text.slice(this.position));
    const token = match ? match[0] : "";
    this.position += token.length;
    if (token === "true") return true;
    if (token === "false") return false;
    const number = Number(token.replace(/_/g, ""));
    return Number.isFinite(number) && token !== "" ? number : token;
  }
}
