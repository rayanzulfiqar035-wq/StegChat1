/** Presentation-only sidebar state. Never stores account or message data. */
const workspace = document.getElementById("workspace");
const toggle = document.getElementById("sidebar-toggle");
if (workspace && toggle) {
  const preference = "stegchat.sidebar.collapsed";
  const compactViewport = window.matchMedia("(max-width: 760px)");
  let collapsed = compactViewport.matches;
  try {
    const saved = localStorage.getItem(preference);
    if (saved !== null && !compactViewport.matches) collapsed = saved === "true";
  } catch { /* Layout remains usable when browser storage is unavailable. */ }
  function render() {
    workspace.dataset.sidebarCollapsed = String(collapsed);
    toggle.setAttribute("aria-expanded", String(!collapsed));
    toggle.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
  }
  toggle.addEventListener("click", () => {
    collapsed = !collapsed;
    render();
    try { localStorage.setItem(preference, String(collapsed)); }
    catch { /* The current page still remembers its own layout. */ }
  });
  compactViewport.addEventListener("change", ({ matches }) => {
    collapsed = matches;
    if (!matches) {
      try { collapsed = localStorage.getItem(preference) === "true"; }
      catch { /* Use the desktop default when preferences cannot be read. */ }
    }
    render();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && compactViewport.matches && !collapsed) {
      collapsed = true;
      render();
      toggle.focus();
    }
  });
  render();
}
