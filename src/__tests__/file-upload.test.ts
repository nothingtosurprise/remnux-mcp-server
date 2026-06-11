/**
 * Tests for file-upload module
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { confineHostPath, validateFilename, validateHostPath } from "../file-upload.js";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

describe("validateFilename", () => {
  describe("valid filenames", () => {
    const validFilenames = [
      "malware.exe",
      "sample.zip",
      "test-file.pdf",
      "document_v2.doc",
      "SAMPLE.EXE",
      "file123.bin",
      "a.txt",
      "my-sample-2024.7z",
    ];

    it.each(validFilenames)("accepts valid filename: %s", (filename) => {
      const result = validateFilename(filename);
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });
  });

  describe("path traversal attempts", () => {
    const pathTraversalAttempts = [
      "../etc/passwd",
      "..\\windows\\system32",
      "foo/../bar",
      "foo/bar",
      "foo\\bar",
      "/etc/passwd",
      "\\windows\\system32",
    ];

    it.each(pathTraversalAttempts)("rejects path traversal: %s", (filename) => {
      const result = validateFilename(filename);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("hidden files (dotfiles)", () => {
    const hiddenFiles = [
      ".bashrc",
      ".hidden",
      ".malware.exe",
    ];

    it.each(hiddenFiles)("accepts hidden file: %s (legitimate sample names)", (filename) => {
      const result = validateFilename(filename);
      expect(result.valid).toBe(true);
    });

    it("rejects '...' (caught by path traversal)", () => {
      const result = validateFilename("...");
      expect(result.valid).toBe(false);
      // This gets caught by '..' check first
      expect(result.error).toBeDefined();
    });
  });

  describe("shell metacharacters", () => {
    const shellMetachars = [
      "file;rm -rf *.txt",
      "file|cat /etc/passwd",
      "file`id`",
      "file$(whoami)",
      "file$HOME",
      "file\necho pwned",
      "file\recho pwned",
      "file'test",
      'file"test',
      "file<input",
      "file>output",
      "file&background",
    ];

    it.each(shellMetachars)("rejects shell metachar: %s", (filename) => {
      const result = validateFilename(filename);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("null bytes", () => {
    it("rejects null byte in filename", () => {
      const result = validateFilename("file\0name.exe");
      expect(result.valid).toBe(false);
      expect(result.error).toContain("null");
    });
  });

  describe("empty and oversized filenames", () => {
    it("rejects empty filename", () => {
      const result = validateFilename("");
      expect(result.valid).toBe(false);
      expect(result.error).toContain("empty");
    });

    it("rejects very long filename", () => {
      const longName = "a".repeat(256);
      const result = validateFilename(longName);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("too long");
    });

    it("accepts filename at max length", () => {
      const maxName = "a".repeat(255);
      const result = validateFilename(maxName);
      expect(result.valid).toBe(true);
    });
  });
});

describe("validateHostPath", () => {
  it("accepts valid absolute paths", () => {
    expect(validateHostPath("/tmp/sample.exe").valid).toBe(true);
    expect(validateHostPath("/home/user/files/malware.bin").valid).toBe(true);
  });

  it("rejects empty path", () => {
    const result = validateHostPath("");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("empty");
  });

  it("rejects relative paths", () => {
    const result = validateHostPath("relative/path.exe");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("absolute");
  });

  it("rejects paths with null bytes", () => {
    const result = validateHostPath("/tmp/file\0name");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("null");
  });

  it("rejects path traversal", () => {
    const result = validateHostPath("/tmp/../etc/passwd");
    expect(result.valid).toBe(false);
    expect(result.error).toContain("traversal");
  });

  it("rejects shell metacharacters", () => {
    const cases = [
      "/tmp/file;rm -rf /",
      "/tmp/file|cat",
      "/tmp/file`id`",
      "/tmp/$HOME/file",
    ];
    for (const p of cases) {
      expect(validateHostPath(p).valid).toBe(false);
    }
  });
});

describe("confineHostPath", () => {
  let root: string;
  let outside: string;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "remnux-ingest-"));
    outside = mkdtempSync(join(tmpdir(), "remnux-outside-"));
    writeFileSync(join(root, "sample.exe"), "data");
    mkdirSync(join(root, "sub"));
    writeFileSync(join(root, "sub", "nested.bin"), "data");
    writeFileSync(join(outside, "secret.txt"), "secret");
    // root/escape is a symlink to the outside directory
    symlinkSync(outside, join(root, "escape"));
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  });

  it("accepts a file directly inside the ingest root and returns its realPath", () => {
    const result = confineHostPath(join(root, "sample.exe"), root);
    expect(result.valid).toBe(true);
    expect(result.realPath).toBeDefined();
  });

  it("accepts a file in a subdirectory of the root", () => {
    expect(confineHostPath(join(root, "sub", "nested.bin"), root).valid).toBe(true);
  });

  it("rejects a file outside the ingest root", () => {
    const result = confineHostPath(join(outside, "secret.txt"), root);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("escapes");
  });

  it("rejects a symlinked-parent escape out of the root", () => {
    // The final component is a regular file, but its parent (root/escape) is a symlink
    // pointing outside the root — realpath resolution must detect the escape.
    const result = confineHostPath(join(root, "escape", "secret.txt"), root);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("escapes");
  });

  it("rejects a nonexistent source (cannot be resolved)", () => {
    const result = confineHostPath(join(root, "does-not-exist.bin"), root);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("host_path could not be resolved");
  });

  it("rejects when the ingest root itself cannot be resolved", () => {
    const result = confineHostPath(join(root, "sample.exe"), join(root, "no-such-root"));
    expect(result.valid).toBe(false);
    expect(result.error).toContain("ingest root could not be resolved");
  });
});
