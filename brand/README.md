# ScriptHound brand

**ScriptHound** sniffs out malicious front-end code. Like a bloodhound, it picks up the scent of a bad script, follows the trail back to whatever loaded it, and raises the alarm.

## Files

| File | Use |
|---|---|
| `scripthound-mark.svg` | App icon / avatar (rounded square) |
| `scripthound-logo.svg` | Horizontal logo with tagline, for light backgrounds |
| `scripthound-logo-dark.svg` | Horizontal logo with tagline, for dark backgrounds |
| `scripthound-wordmark.svg` | Horizontal logo without tagline |
| `png/` | PNG exports: mark at 512 / 180 / 64 px, logos at 3× |

### Simple version

A flatter take: one silhouette, an ear line, an eye, a nose and the scent arcs. It has no collar, brow or shading, and it stays legible down to 16–32 px (favicons, GitHub avatars, Slack).

| File | Use |
|---|---|
| `scripthound-mark-simple.svg` | Icon, navy background |
| `scripthound-mark-simple-amber.svg` | Icon, amber background |
| `scripthound-mark-simple-mono.svg` | Single-color, transparent background (print, stamps, embossing) |
| `scripthound-logo-simple.svg` / `-dark.svg` | Horizontal logo for light / dark backgrounds |
| `png/*-simple-*` | PNG exports, including a 32 px favicon |

The SVG text is converted to outlines, so it renders the same everywhere with no font install. In a README, use: `<img src="brand/scripthound-logo.svg" alt="ScriptHound" height="64">`

## Colors

| Name | Hex | Use |
|---|---|---|
| Kennel navy | `#14213D` | Icon background, wordmark "Script" |
| Alert amber | `#F77F00` | "Hound", collar, scent trail (the alarm) |
| Cream | `#F4F1EA` | Hound, wordmark on dark |
| Ear brown | `#B5835A` | Ear |
| Slate | `#5B6475` | Tagline on light |

## Type

Wordmark and tagline: **Inter** ExtraBold / Medium (SIL Open Font License). Collar `</>`: DejaVu Sans Mono Bold.

## Tagline

> Sniffs out malicious front-end code

## Notes

- Keep clear space around the mark of at least the collar's height.
- Below about 32 px the ear and collar details blur. If a favicon is needed, a simplified 16/32 px version would read better.

## Trademark

"ScriptHound" and the ScriptHound logo (all files in this folder) are trademarks of Kanopi Studios. The ScriptHound **code** is licensed under the Apache License 2.0, but section 6 of that license grants no rights to these trademarks. You may refer to ScriptHound by name (for example, "scanned with ScriptHound"). Don't use the name or logo for a modified version, a fork or another product, or in a way that suggests Kanopi Studios endorses something, without permission.

The wordmark is drawn from Inter (SIL Open Font License), converted to outlines.
