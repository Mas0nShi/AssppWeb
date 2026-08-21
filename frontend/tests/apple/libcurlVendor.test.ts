import { X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const expectedFingerprint =
  "B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24";

describe("vendored libcurl.js trust store", () => {
  it("embeds the pinned official Apple Root CA in the WASM payload", () => {
    const moduleSource = readFileSync(
      resolve("src/vendor/libcurl/libcurl_full.mjs"),
      "utf8",
    );
    const match = moduleSource.match(
      /data:application\/octet-stream;base64,([A-Za-z0-9+/=]+)/,
    );
    expect(match).not.toBeNull();

    const wasm = Buffer.from(match![1], "base64");
    const appleRoot = readFileSync(
      resolve("src/vendor/libcurl/AppleIncRootCertificate.cer"),
    );
    const certificate = new X509Certificate(appleRoot);

    expect(certificate.fingerprint256).toBe(expectedFingerprint);
    expect(wasm.includes(appleRoot)).toBe(true);
  });
});
