// Nombre de nuestro caché (como una caja para guardar archivos)
const CACHE_NAME = 'finwise-cache-v1';

// Lista de archivos base que SIEMPRE queremos guardar
// Estos son los que permiten que la app "abra" sin conexión
const urlsToCache = [
  '/', // La página principal
  '/login', // La página de login
  '/register', // La página de registro
  '/static/manifest.json', // El pasaporte
  '/static/favicon.png', // El icono
  '/static/icon-192.png',
  '/static/icon-512.png'
  // Nota: No podemos cachear los CSS/JS de las librerías externas (Chart.js, SweetAlert)
  // porque vienen de 'cdn.jsdelivr.net', pero la app principal sí cargará.
];

// --- 1. INSTALACIÓN ---
// Se ejecuta la primera vez que el usuario visita la página
self.addEventListener('install', event => {
  console.log('Service Worker: Instalando...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Service Worker: Abriendo caché y guardando archivos base');
        return cache.addAll(urlsToCache);
      })
      .then(() => self.skipWaiting()) // Activa el SW inmediatamente
  );
});

// --- 2. ACTIVACIÓN ---
// Se ejecuta después de instalar, limpia cachés viejos si los hay
self.addEventListener('activate', event => {
  console.log('Service Worker: Activando...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.filter(name => name !== CACHE_NAME)
          .map(name => caches.delete(name)) // Borra cualquier caché con nombre antiguo
      );
    })
  );
  return self.clients.claim(); // Toma control de la página
});

// --- 3. INTERCEPTAR PETICIONES (FETCH) ---
// ¡Aquí ocurre la magia offline!
self.addEventListener('fetch', event => {
  // Solo respondemos a peticiones GET (no a POSTs, esos sí necesitan internet)
  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request)
      .then(cachedResponse => {
        // Estrategia: "Cache First"
        // 1. Si está en el caché, lo servimos desde ahí (¡súper rápido!)
        if (cachedResponse) {
          return cachedResponse;
        }

        // 2. Si no está en caché, vamos a la red a buscarlo
        return fetch(event.request);
      })
  );
});