// ============================================================
// B1 — Bundle parsers: SRI + chunk discovery + sourcemap regex
// ============================================================
import { describe, it, expect } from 'vitest';
import { findMissingSri, findChunkUrls } from '../src/engines/bundle-scan';

const PAGE = 'https://myapp.lovable.app/';

describe('findMissingSri', () => {
  it('flags a cross-origin script without integrity', () => {
    const html = `<script src="https://cdn.example.com/lib.js"></script>`;
    const issues = findMissingSri(html, PAGE);
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ tag: 'script', url: 'https://cdn.example.com/lib.js' });
  });

  it('does NOT flag a cross-origin script that has integrity', () => {
    const html = `<script src="https://cdn.example.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>`;
    expect(findMissingSri(html, PAGE)).toEqual([]);
  });

  it('ignores same-origin scripts', () => {
    const html = `<script src="https://myapp.lovable.app/assets/index.js"></script>`;
    expect(findMissingSri(html, PAGE)).toEqual([]);
  });

  it('ignores relative scripts', () => {
    const html = `<script src="/assets/index.js"></script>`;
    expect(findMissingSri(html, PAGE)).toEqual([]);
  });

  it('flags a cross-origin stylesheet link without integrity, ignores icon links', () => {
    const html = `
      <link rel="stylesheet" href="https://cdn.example.com/a.css">
      <link rel="icon" href="https://cdn.example.com/fav.ico">`;
    const issues = findMissingSri(html, PAGE);
    expect(issues).toHaveLength(1);
    expect(issues[0].tag).toBe('link');
  });
});

describe('findChunkUrls', () => {
  it('resolves same-page .js chunks to absolute URLs, bounded', () => {
    const html = `
      <script src="/assets/index-abc.js"></script>
      <script src="/assets/vendor-def.js"></script>`;
    const urls = findChunkUrls(html, PAGE, 6);
    expect(urls).toContain('https://myapp.lovable.app/assets/index-abc.js');
    expect(urls).toContain('https://myapp.lovable.app/assets/vendor-def.js');
  });

  it('respects the limit', () => {
    const html = Array.from({ length: 10 }, (_, i) => `<script src="/a-${i}.js"></script>`).join('');
    expect(findChunkUrls(html, PAGE, 3)).toHaveLength(3);
  });
});

describe('inline sourcemap regex', () => {
  // mirror of SOURCEMAP_RE behavior used inside scanBundle
  const re = /\/\/[#@]\s*sourceMappingURL=(\S+)/g;
  it('matches inline data: maps', () => {
    const body = 'console.log(1)\n//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ==';
    const m = [...body.matchAll(re)];
    expect(m[0][1].startsWith('data:')).toBe(true);
  });
  it('matches external .map refs', () => {
    const body = 'x()\n//# sourceMappingURL=index-abc.js.map';
    const m = [...body.matchAll(re)];
    expect(m[0][1]).toBe('index-abc.js.map');
  });
});
