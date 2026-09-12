import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Logs } from "../src/components/logs.tsx";

const logs = [
  {
    id: 1,
    timestamp: 1_700_000_000,
    level: "INFO",
    message: "Configuration updated",
    actor: "admin",
  },
  {
    id: 2,
    timestamp: 1_700_000_001,
    level: "ERROR",
    message: "Adapter attach failed",
    actor: "system",
  },
];

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  close = vi.fn();

  constructor() {
    MockWebSocket.instances.push(this);
  }
}

describe("Logs", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    vi.stubGlobal("WebSocket", MockWebSocket);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(logs), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loads events, filters by level, and keeps the filtered count accurate", async () => {
    render(<Logs />);

    await waitFor(() => {
      expect(screen.getByText("Configuration updated")).toBeInTheDocument();
    });
    expect(screen.getByText("Adapter attach failed")).toBeInTheDocument();
    expect(screen.getByText("2 visible of 2 events")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "ERROR" }));

    expect(screen.queryByText("Configuration updated")).not.toBeInTheDocument();
    expect(screen.getByText("Adapter attach failed")).toBeInTheDocument();
    expect(screen.getByText("1 visible of 2 events")).toBeInTheDocument();
  });

  it("prepends valid WebSocket events and closes the socket on unmount", async () => {
    const { unmount } = render(<Logs />);
    await waitFor(() => expect(MockWebSocket.instances).toHaveLength(1));

    const socket = MockWebSocket.instances[0];
    socket.onmessage?.({
      data: JSON.stringify({
        id: 3,
        timestamp: 1_700_000_002,
        level: "WARN",
        message: "Policy changed",
        actor: null,
      }),
    } as MessageEvent<string>);

    await waitFor(() => {
      expect(screen.getByText("Policy changed")).toBeInTheDocument();
      expect(screen.getByText("3 visible of 3 events")).toBeInTheDocument();
    });

    unmount();
    expect(socket.close).toHaveBeenCalledOnce();
  });

  it("shows the API error instead of an empty success state", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(
      () => {},
    );
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response(null, { status: 503, statusText: "Service Unavailable" }),
    );

    render(<Logs />);

    await waitFor(() => {
      expect(screen.getAllByText("Log request failed (503)")).toHaveLength(2);
    });
    expect(
      screen.getByText(
        "Events emitted by the firewall and HTTP control plane appear here.",
      ),
    )
      .toBeInTheDocument();
    expect(consoleError).toHaveBeenCalledWith(
      "Failed to load firewall logs:",
      expect.objectContaining({ message: "Log request failed (503)" }),
    );
  });
});
