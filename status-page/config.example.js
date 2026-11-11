// SPDX-License-Identifier: MIT OR Apache-2.0
// Copy to config.js on the status host (config.js is not in git).
// The API must list this page's origin in [server] status_page_origins.
window.SENTINEL_STATUS = {
  api: "https://portal.example.org/api/v1/status", // the platform's public status
  portal: "https://portal.example.org",            // linked from the footer
  refreshSeconds: 15,
};
