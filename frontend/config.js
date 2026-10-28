// Backend base URL. "" = same origin (the FastAPI dev server also serves this
// frontend, which avoids Codespaces port-auth/CORS issues). For Vercel, set the
// Render URL here, e.g. "https://tracii-api.onrender.com". Never put API keys here.
window.TRACII_API = window.TRACII_API ?? "";
