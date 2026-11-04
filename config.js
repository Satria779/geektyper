// API_BASE kosong = lewat proxy server.js (bebas CORS). Isi URL penuh jika API mengizinkan CORS.
export const API_BASE = '';
export const MEDIA_BASE = 'https://cdncid.csmcscns.id';
export const ROUTES = {
  hero: '/v1/manga/heroSlider', latest: '/v1/manga/latest', popular: '/v1/manga/popularToday',
  all: '/v1/manga/allComics', filter: '/v1/manga/filter', search: '/v1/manga/search',
  detail: s => `/v1/manga/mangaDetail/${encodeURIComponent(s)}`,
  reading: s => `/v1/manga/readingPage/${encodeURIComponent(s)}`,
  related: s => `/v1/manga/related/${encodeURIComponent(s)}`,
};
