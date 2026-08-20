import { beforeEach, describe, expect, it, vi } from "vitest";
import { buildPlist } from "../../src/apple/plist";
import { authenticate } from "../../src/apple/authenticate";
import { appleRequest } from "../../src/apple/request";
import { fetchBag } from "../../src/apple/bag";

vi.mock("../../src/apple/request", () => ({
  appleRequest: vi.fn(),
}));

vi.mock("../../src/apple/bag", () => ({
  fetchBag: vi.fn(),
  defaultAuthURL:
    "https://auth.itunes.apple.com/auth/v1/native/fast/",
  legacyAuthURL:
    "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
}));

describe("apple/authenticate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("sets guid query exactly once from bag endpoint", async () => {
    vi.mocked(fetchBag).mockResolvedValue({
      authURL:
        "https://auth.itunes.apple.com/auth/v1/native/fast/?foo=1&guid=old-value",
    });
    vi.mocked(appleRequest).mockResolvedValue({
      status: 200,
      statusText: "OK",
      headers: {},
      rawHeaders: [],
      body: buildPlist({
        accountInfo: {
          appleId: "test@example.com",
          address: {
            firstName: "Test",
            lastName: "User",
          },
        },
        passwordToken: "token",
        dsPersonId: "123",
      }),
    });

    await authenticate(
      "test@example.com",
      "password",
      undefined,
      undefined,
      "aabbccddeeff",
    );

    const requestCall = vi.mocked(appleRequest).mock.calls[0][0];
    const endpoint = new URL(`https://${requestCall.host}${requestCall.path}`);

    expect(requestCall.headers).toEqual({
      "Content-Type": "application/x-www-form-urlencoded",
    });
    expect(endpoint.searchParams.get("guid")).toBe("aabbccddeeff");
    expect(endpoint.searchParams.getAll("guid")).toHaveLength(1);
    expect(endpoint.searchParams.get("foo")).toBe("1");
  });

  it("falls back from an empty native response and preserves the POST across the pod redirect", async () => {
    vi.mocked(fetchBag).mockResolvedValue({
      authURL: "https://auth.itunes.apple.com/auth/v1/native/fast/",
    });
    vi.mocked(appleRequest)
      .mockResolvedValueOnce({
        status: 204,
        statusText: "No Content",
        headers: {},
        rawHeaders: [],
        body: "",
      })
      .mockResolvedValueOnce({
        status: 302,
        statusText: "Found",
        headers: {
          location:
            "https://p7-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate?Pod=7&PRH=7",
        },
        rawHeaders: [],
        body: "",
      })
      .mockResolvedValueOnce({
        status: 200,
        statusText: "OK",
        headers: {
          pod: "7",
          "x-set-apple-store-front": "143441-1,29",
        },
        rawHeaders: [],
        body: buildPlist({
          accountInfo: {
            appleId: "test@example.com",
            address: {
              firstName: "Test",
              lastName: "User",
            },
          },
          passwordToken: "token",
          dsPersonId: "123",
        }),
      });

    const account = await authenticate(
      "test@example.com",
      "password",
      undefined,
      undefined,
      "aabbccddeeff",
    );

    const requests = vi.mocked(appleRequest).mock.calls.map(([request]) =>
      request,
    );
    expect(requests.map(({ host }) => host)).toEqual([
      "auth.itunes.apple.com",
      "buy.itunes.apple.com",
      "p7-buy.itunes.apple.com",
    ]);
    expect(requests[1].path).toBe(
      "/WebObjects/MZFinance.woa/wa/authenticate?guid=aabbccddeeff",
    );
    expect(requests[2].path).toBe(
      "/WebObjects/MZFinance.woa/wa/authenticate?Pod=7&PRH=7",
    );
    expect(requests[1].body).toBe(requests[0].body);
    expect(requests[2].body).toBe(requests[0].body);
    expect(account.pod).toBe("7");
    expect(account.store).toBe("143441");
  });
});
