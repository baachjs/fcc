/* -------------------------------------------------
   Simple Service Worker for Secure Share Chat
   ------------------------------------------------- */

const CACHE_NAME = "secure-chat-v1";
const ASSETS = [
  "/", // root (index.html)
  "/index.html",
  "/app.js",
  "/light.css",
  "/dark.css",
  "/manifest.json",
  "/icon-192.png",
  "/icon-512.png",
];

// Install – cache all essential assets
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)),
  );
});

// Activate – clean up old caches (if any)
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)),
        ),
      ),
  );
});

// Fetch – serve from cache first, fall back to network
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return; // ignore non‑GET
  event.respondWith(
    caches
      .match(event.request)
      .then((cached) => cached || fetch(event.request)),
  );
});
