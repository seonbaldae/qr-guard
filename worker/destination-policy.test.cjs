const test = require("node:test");
const assert = require("node:assert/strict");
const {
  UnsafeDestinationError,
  assertPublicHttpUrl,
} = require("./destination-policy.cjs");

const publicDns = async () => [
  { address: "93.184.216.34", family: 4 },
  { address: "2606:2800:220:1:248:1893:25c8:1946", family: 6 },
];

test("공개 HTTP URL을 정규화해 허용한다", async () => {
  assert.equal(
    await assertPublicHttpUrl("HTTPS://EXAMPLE.COM/path?x=1", publicDns),
    "https://example.com/path?x=1"
  );
});

for (const value of [
  "http://127.0.0.1/",
  "http://127.1/",
  "http://0177.0.0.1/",
  "http://0x7f000001/",
  "http://2130706433/",
  "http://[::1]/",
  "http://[::ffff:127.0.0.1]/",
  "http://169.254.169.254/latest/meta-data/",
  "http://localhost/",
  "https://user:secret@example.com/",
  "https://example.com:8443/",
  "file:///etc/passwd",
]) {
  test(`안전하지 않은 목적지를 차단한다: ${value}`, async () => {
    await assert.rejects(
      assertPublicHttpUrl(value, publicDns),
      UnsafeDestinationError
    );
  });
}

for (const address of [
  "10.0.0.1",
  "172.16.0.1",
  "192.168.0.1",
  "127.0.0.1",
  "169.254.169.254",
  "::1",
  "fc00::1",
  "fe80::1",
]) {
  test(`DNS의 비공개 주소를 차단한다: ${address}`, async () => {
    await assert.rejects(
      assertPublicHttpUrl("https://example.com/", async () => [
        { address: "93.184.216.34", family: 4 },
        { address, family: address.includes(":") ? 6 : 4 },
      ]),
      UnsafeDestinationError
    );
  });
}

test("DNS 결과가 없으면 차단한다", async () => {
  await assert.rejects(
    assertPublicHttpUrl("https://example.com/", async () => []),
    UnsafeDestinationError
  );
});
