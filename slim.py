#!/usr/bin/env python3
"""Slim the meowhash __init__.py by removing section banners, docstrings, blank lines."""
import re

with open('src/meowhash_pure/__init__.py', 'r') as f:
    lines = f.readlines()

result = []
i = 0
while i < len(lines):
    line = lines[i]
    # Remove section banners: # ----... and # description lines
    if (line.startswith('# ---') or
        (i+1 < len(lines) and lines[i+1].startswith('# ---')) or
        re.match(r'# \d+-byte', line)):
        i += 1
        continue
    # Skip blank lines between def/class blocks
    if (line.startswith(('def ', 'class ')) and
        result and result[-1].strip() == '' and
        len(result) >= 2 and result[-2].startswith(('def ', 'class '))):
        result.pop()
    result.append(line)
    i += 1

content = ''.join(result)
# Remove docstrings from helper functions only (not from public API)
content = re.sub(r'(\ndef _[a-z_]+\([^)]*\)[^:]*?\n)    """[^"]*?"""', r'\1', content)
# Remove type hints from helper functions to save space
content = re.sub(r'(\ndef _[a-z_]+\()([^)]+)\)', lambda m: m.group(1) + re.sub(r': \w+', '', m.group(2)) + ')', content)

with open('src/meowhash_pure/__init__.py', 'w') as f:
    f.write(content)
print(f"done, {len(content.splitlines())} lines")
