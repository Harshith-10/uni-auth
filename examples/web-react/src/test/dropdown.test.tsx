// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { Navbar } from "../components/Navbar";
import { AdminConsoleCard } from "../components/AdminConsoleCard";

describe("Dropdown menu test", () => {
  it("renders Navbar and clicks avatar dropdown trigger", async () => {
    document.body.innerHTML = "";
    const container = document.createElement("div");
    document.body.appendChild(container);

    const user = {
      id: "u1",
      name: "Admin User",
      email: "admin@example.com",
      role: "admin",
    };

    const root = (
      <Navbar
        session={{ user }}
        isAdmin={true}
        userRole="admin"
        impersonatedBy={null}
        theme="dark"
        onToggleTheme={() => {}}
        onSignOut={() => {}}
        onStopImpersonating={() => {}}
        onOpenAuthModal={() => {}}
        onSelectTab={() => {}}
      />
    );

    const reactRoot = createRoot(container);
    await act(async () => {
      reactRoot.render(root);
    });

    const buttons = Array.from(container.querySelectorAll("button"));
    const avatarBtn = buttons[buttons.length - 1];
    expect(avatarBtn).toBeDefined();

    if (avatarBtn) {
      await act(async () => {
        avatarBtn.click();
      });
      // Ensure the menu items are in the DOM and rendered without throwing
      const popup = document.querySelector("[data-slot='dropdown-menu-content']");
      expect(popup).not.toBeNull();
      expect(popup?.textContent).toContain("Admin User");
    }
  });

  it("renders AdminConsoleCard and clicks actions dropdown trigger", async () => {
    document.body.innerHTML = "";
    const container = document.createElement("div");
    document.body.appendChild(container);

    const users = [
      {
        id: "u1",
        name: "Admin User",
        email: "admin@example.com",
        role: "admin",
        banned: false,
        emailVerified: true,
      },
      {
        id: "u2",
        name: "Alice",
        email: "alice@example.com",
        role: "user",
        banned: false,
        emailVerified: true,
      },
    ];

    const root = (
      <AdminConsoleCard
        users={users}
        totalUsers={2}
        isLoading={false}
        search=""
        onSearchChange={() => {}}
        onRefresh={() => {}}
        onToggleRole={async () => {}}
        onToggleBan={async () => {}}
        onImpersonate={async () => {}}
        onDeleteUser={async () => {}}
        onCreateUser={async () => {}}
        currentUserId="u1"
      />
    );

    const reactRoot = createRoot(container);
    await act(async () => {
      reactRoot.render(root);
    });

    const actionButtons = Array.from(container.querySelectorAll("button[title='Actions menu']"));
    expect(actionButtons.length).toBeGreaterThan(0);
    if (actionButtons[0]) {
      await act(async () => {
        (actionButtons[0] as HTMLElement).click();
      });
      const popup = document.querySelector("[data-slot='dropdown-menu-content']");
      expect(popup).not.toBeNull();
      expect(popup?.textContent).toContain("User Actions");
    }
  });
});
