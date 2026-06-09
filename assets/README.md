# Brand assets

| File | Use |
|------|-----|
| `logo.jpg` | Canonical Legion brand mark (1254×1254). Use for avatars and the repo **social preview**. |
| `logo.svg` | Scalable chevron mark in the brand palette (green/red on transparent). Use in docs/READMEs at any size. |
| `banner.svg` | Wide header (1280×640) — wordmark + tagline. Good source for the social preview banner. |

## Palette

- Matrix green: `#4ade80` → `#15803d`
- Alert red: `#f87171` → `#b91c1c`
- Background: `#000000`

## Set the repo social preview

GitHub → repo **Settings → General → Social preview → Upload an image**
(recommended 1280×640). Export `banner.svg` to PNG first, e.g.:

```bash
# requires librsvg (rsvg-convert) or Inkscape
rsvg-convert -w 1280 -h 640 assets/banner.svg -o social-preview.png
# or
inkscape assets/banner.svg --export-type=png -w 1280 -h 640 -o social-preview.png
```

Or just upload `logo.jpg` directly if you prefer the square mark.
