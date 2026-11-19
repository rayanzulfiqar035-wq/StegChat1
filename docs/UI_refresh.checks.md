# Workspace UI refresh

The root URL now opens login. Signed-in visitors retain the existing automatic
redirect to Chat. Login and registration share a responsive split layout with
a local messaging illustration; login links directly to account creation.

Chat, the transport selector, the image composer, placeholders and the opt-in
local lab share a collapsible sidebar. Chat and Stego are the primary links.
Only the collapsed/expanded layout preference is stored; no messages, files,
keys or account data are stored by the navigation script. On mobile the sidebar
starts collapsed, expands over the content, and closes with Escape.

## New presentation routes

| Path | Behavior |
| --- | --- |
| `/` | Redirect to existing `/login` |
| `/stego` | Choose Image, Audio or Text |
| `/stego/image` | Darker image composer, local PNG preview, recipient and message fields |
| `/stego/audio` | Coming-soon preview with disabled inputs; no upload/send endpoint |
| `/stego/text` | Coming-soon preview with disabled inputs; no upload/send endpoint |

All stego pages require the existing session authentication. The standalone lab
keeps its existing `STEGO_LAB` flag and its existing authentication requirement.

## Existing behavior preserved

The image page loads the same `chat.js` client and shares its DOM control IDs.
The new page requires a valid cover both in button state and at submission,
preventing a normal text envelope from being sent by mistake. Removing a cover
clears its local preview and disables image sending until another valid PNG is
selected. Incoming messages remain visible and follow the existing signature,
decryption, rendering and recipient acknowledgment order.

The encryption and steganography modules, key store, API, relay event handlers,
queue, rate limits, audit rules and database schema are unchanged. The local
image preview uses a revocable object URL; filenames use textContent. No new
dependencies, remote images, inline scripts or CSP exceptions were added.

## Verification

- Complete pytest suite: **103 passed**. The seven new route checks cover login
  entry, protected presentation pages and disabled placeholders. The shared
  test CSRF helper follows the new root redirect.
- Real Chrome HTTPS/WSS suite: **80 passed, 0 failed**. New checks exercise the
  registration link, illustration, sidebar state, transport navigation, both
  placeholders, saved identity across pages, mandatory-cover guard, local PNG
  preview and mobile layout. The existing offline encrypted PNG delivery,
  acknowledgments, tamper rejection and text security checks still pass.
- Node position-stream/capacity suite: **5 passed**.
- Bandit application/analysis scan, JavaScript syntax and Git whitespace checks:
  passed.
- Desktop and mobile screenshots were visually reviewed. The mobile sidebar
  was checked in collapsed and expanded states without squeezing the composer.

Optional screenshots from the isolated test suite can be reproduced by setting
`UI_SCREENSHOT_DIR` to a temporary directory before running
`node tests/browser_step6.mjs`. These UI images contain only synthetic test
accounts; the separate lab screenshot includes a disposable lab key and should
remain outside committed evidence.
