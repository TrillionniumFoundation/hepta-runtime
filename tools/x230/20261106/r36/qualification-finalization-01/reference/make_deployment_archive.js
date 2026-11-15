// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// Deterministic USTAR plus valid gzip with stored DEFLATE blocks. No compression
// ratio claim: archive overhead is bounded; every original UTF-8 byte is retained.
function makeDeploymentArchive(h, files) {
  const parts = [];
  function text(header, offset, length, value) {
    const bytes = h.utf8(value);
    if (bytes.length > length) throw new Error("USTAR field overflow");
    header.set(bytes, offset);
  }
  function octal(header, offset, length, value) {
    const digits = value.toString(8).padStart(length - 1, "0");
    if (digits.length !== length - 1) throw new Error("USTAR integer overflow");
    text(header, offset, length, digits + "\0");
  }
  for (const name of Object.keys(files).sort()) {
    if (name.startsWith("/") || name.split("/").some(x => x === ".." || !x))
      throw new Error("unsafe member path");
    const body = h.utf8(files[name]), header = new Uint8Array(512);
    text(header, 0, 100, name); octal(header, 100, 8, 0o600);
    octal(header, 108, 8, 0); octal(header, 116, 8, 0);
    octal(header, 124, 12, body.length); octal(header, 136, 12, 0);
    header.fill(32, 148, 156); header[156] = 48;
    text(header, 257, 6, "ustar\0"); text(header, 263, 2, "00");
    const checksum = Array.from(header).reduce((a, b) => a + b, 0);
    text(header, 148, 8, checksum.toString(8).padStart(6, "0") + "\0 ");
    parts.push(header, body, new Uint8Array((512 - body.length % 512) % 512));
  }
  parts.push(new Uint8Array(1024));
  const tar = h.concat(parts);
  let crc = 0xffffffff;
  for (const byte of tar) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  const gz = [Uint8Array.from([31, 139, 8, 0, 0, 0, 0, 0, 0, 255])];
  for (let offset = 0; offset < tar.length; offset += 65535) {
    const length = Math.min(65535, tar.length - offset), inverse = (~length) & 0xffff;
    gz.push(Uint8Array.from([offset + length === tar.length ? 1 : 0,
                            length & 255, length >>> 8, inverse & 255, inverse >>> 8]));
    gz.push(tar.slice(offset, offset + length));
  }
  const footer = new Uint8Array(8);
  for (let i = 0; i < 4; i++) {
    footer[i] = (crc >>> (8 * i)) & 255;
    footer[4 + i] = (tar.length >>> (8 * i)) & 255;
  }
  gz.push(footer);
  return {tar, gzip: h.concat(gz)};
}
makeDeploymentArchive;
