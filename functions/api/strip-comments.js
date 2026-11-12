// Membuang komentar dari source Worker sebelum dikirim ke Cloudflare.
//
// Kenapa: upload lewat API mentah (POST/PUT worker script) dengan source apa adanya
// menghasilkan Worker yang mati beberapa saat setelah deploy (`/health` 500, error 1101),
// sedangkan source yang sama setelah komentarnya dibuang berjalan stabil (diukur: 12/12
// request OK selama 2 menit + tunnel VLESS lulus). `wrangler deploy` juga tidak pernah
// mengirim komentar karena esbuild membundel lebih dulu. Transformasi ini murni kosmetik
// (komentar tidak memengaruhi semantik), jadi aman.
//
// Scanner kecil ini menghormati string ('...', "..."), template literal (`...`), escape
// backslash, dan blok komentar. Regex literal diperlakukan sebagai kode biasa — cukup untuk
// template Worker di repo ini (tidak ada regex yang memuat `//`).

export function stripComments(source) {
  let out = "";
  let i = 0;
  const n = source.length;
  let state = "code"; // code | line | block | single | double | template

  while (i < n) {
    const ch = source[i];
    const next = i + 1 < n ? source[i + 1] : "";

    if (state === "code") {
      if (ch === "/" && next === "/") { state = "line"; i += 2; continue; }
      if (ch === "/" && next === "*") { state = "block"; i += 2; continue; }
      if (ch === "'") { state = "single"; out += ch; i++; continue; }
      if (ch === '"') { state = "double"; out += ch; i++; continue; }
      if (ch === "`") { state = "template"; out += ch; i++; continue; }
      out += ch; i++; continue;
    }

    if (state === "line") {
      if (ch === "\n") { state = "code"; out += ch; }
      i++; continue;
    }

    if (state === "block") {
      if (ch === "*" && next === "/") { state = "code"; i += 2; } else { i++; }
      continue;
    }

    if (state === "single" || state === "double") {
      const quote = state === "single" ? "'" : '"';
      if (ch === "\\") { out += ch + next; i += 2; continue; }
      out += ch; i++;
      if (ch === quote) state = "code";
      continue;
    }

    // template literal
    if (ch === "\\") { out += ch + next; i += 2; continue; }
    out += ch; i++;
    if (ch === "`") state = "code";
  }

  // rapikan sisa baris kosong berlebih (kosmetik, sama seperti hasil esbuild)
  return out.replace(/\n{3,}/g, "\n\n");
}

export default stripComments;