/** Explicit contact requests; independent from cryptographic key trust. */
export function createPhonebook({ socket, onChange }) {
  const element = (id) => document.getElementById(id);
  const accepted = new Set();
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  let refreshNumber = 0;
  let changing = false;

  function status(message) { element("phonebook-status").textContent = message; }
  function node(tag, text, className = "") {
    const result = document.createElement(tag);
    // SECURITY: usernames and all other dynamic labels are plain text.
    result.textContent = text;
    result.className = className;
    return result;
  }
  function action(label, operation) {
    const button = node("button", label, "btn btn--ghost btn--small");
    button.type = "button";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try { await operation(); }
      finally { button.disabled = false; }
    });
    return button;
  }
  function render(contacts) {
    const list = element("phonebook-list");
    const options = element("phonebook-options");
    list.replaceChildren(); options.replaceChildren();
    if (!contacts.length) list.append(node("li", "Your phonebook is empty. Send a request to someone you know.", "phonebook-empty"));
    for (const contact of contacts) {
      const row = node("li", "", "phonebook-entry");
      row.dataset.username = contact.username;
      row.dataset.status = contact.status;
      const identity = node("div", "", "phonebook-identity");
      identity.append(node("strong", contact.username), node("span", {
        accepted: "Approved contact", incoming: "Wants to connect", outgoing: "Waiting for acceptance",
      }[contact.status]));
      const actions = node("div", "", "phonebook-actions");
      const path = "/api/contacts/" + encodeURIComponent(contact.username);
      if (contact.status === "accepted") {
        const option = document.createElement("option");
        option.value = contact.username;
        options.append(option);
        actions.append(action("Chat", () => {
          const recipient = element("recipient-input");
          recipient.value = contact.username;
          recipient.dispatchEvent(new Event("input"));
          recipient.focus();
        }));
      } else if (contact.status === "incoming") {
        actions.append(action("Accept", () => mutate(path + "/accept", "POST")));
      }
      actions.append(action({accepted: "Remove", incoming: "Decline", outgoing: "Cancel request"}[contact.status],
        () => mutate(path, "DELETE")));
      row.append(identity, actions); list.append(row);
    }
  }
  async function refresh() {
    const number = ++refreshNumber;
    try {
      const response = await fetch("/api/contacts", { cache: "no-store" });
      if (!response.ok) throw new Error("phonebook unavailable");
      const data = await response.json();
      if (number !== refreshNumber) return;
      accepted.clear();
      for (const contact of data.contacts) if (contact.status === "accepted") accepted.add(contact.username);
      render(data.contacts); onChange();
    } catch {
      if (number !== refreshNumber) return;
      // SECURITY: an unavailable phonebook disables sending rather than bypassing consent.
      accepted.clear();
      element("phonebook-options").replaceChildren();
      element("phonebook-list").replaceChildren(node("li", "Phonebook unavailable. Refresh to retry.", "phonebook-empty"));
      onChange();
      status("Could not load your phonebook. Check your connection and refresh it.");
    }
  }
  async function mutate(path, method, body) {
    if (changing) return;
    changing = true;
    element("phonebook-request-button").disabled = true;
    try {
      const response = await fetch(path, { method,
        headers: { "X-CSRFToken": csrf, "Content-Type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok) {
        const messages = {
          400: "Enter a different valid username.", 401: "Sign in again to update your phonebook.",
          403: "Only the recipient can accept a request.", 404: "That user or request was not found.",
          409: "That contact or request already exists. Check your phonebook below.",
          429: "Too many phonebook changes. Try again later.",
        };
        status(messages[response.status] || "Could not update your phonebook. Try again.");
        await refresh(); return;
      }
      status(path.endsWith("/accept") ? "Contact accepted. You can now message each other."
        : method === "DELETE" ? "Contact or request removed. Messaging is blocked."
          : "Request sent. Messaging unlocks when they accept.");
      if (body) element("phonebook-username").value = "";
      await refresh();
    } catch { status("Could not update your phonebook. Check your connection and retry."); }
    finally { changing = false; element("phonebook-request-button").disabled = false; }
  }
  element("phonebook-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const username = element("phonebook-username").value.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,32}$/.test(username)) { status("Enter a valid username, 3–32 letters, digits or underscores."); return; }
    void mutate("/api/contacts", "POST", { username });
  });
  element("phonebook-refresh").addEventListener("click", () => { status(""); void refresh(); });
  socket.on("contacts_changed", refresh);
  socket.on("connect", refresh);
  return { isAccepted: (username) => accepted.has(username), refresh };
}
