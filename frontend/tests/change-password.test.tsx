import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { ChangePassword } from "../src/components/change-password.tsx";

describe("ChangePassword", () => {
  it("rejects a password that is too short without making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <ChangePassword />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "short" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "short" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Set password" }));

    expect(
      await screen.findByRole("alert"),
    ).toHaveTextContent("Password must be between 12 and 120 characters.");
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("rejects mismatched passwords without making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <ChangePassword />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "ValidPassword123!" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "DifferentPassword123!" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Set password" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Passwords do not match.",
    );
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("sends the matching password to the API", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(null, { status: 204 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <ChangePassword />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "ValidPassword123!" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "ValidPassword123!" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Set password" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/change_password",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
        body: JSON.stringify({ password: "ValidPassword123!" }),
      }),
    );
    vi.unstubAllGlobals();
  });

  it("clears authentication when the session is rejected", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("Session expired", { status: 409 }),
    );
    const onLogout = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MemoryRouter>
        <ChangePassword onLogout={onLogout} />
      </MemoryRouter>,
    );

    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "ValidPassword123!" },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: "ValidPassword123!" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Set password" }));

    await waitFor(() => expect(onLogout).toHaveBeenCalledOnce());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/change_password",
      expect.objectContaining({ method: "POST" }),
    );
    vi.unstubAllGlobals();
  });
});
