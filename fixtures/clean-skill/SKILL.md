---
name: markdown-toc-helper
description: Generates a clean Markdown table of contents from heading lines in documentation files.
---

# Markdown TOC Helper

Formats clean nested anchor links for standard Markdown documentation without external tools or network calls.

## Generate Sample TOC

```python
import re


def build_toc(markdown_text: str) -> list[str]:
    entries: list[str] = []
    for raw in markdown_text.splitlines():
        m = re.match(r"^(#{1,3})\s+(.+)$", raw.strip())
        if not m:
            continue
        depth = len(m.group(1))
        title = m.group(2).strip()
        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
        entries.append(f"{'  ' * (depth - 1)}- [{title}](#{slug})")
    return entries


sample = "# Overview\n## Setup\n### Verification\n"
print("\n".join(build_toc(sample)))
```
