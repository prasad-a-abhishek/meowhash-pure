#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')
import meowhash_pure
h = meowhash_pure.meow64(b'hello', 0)
print(f'hello={h:#x}')
h2 = meowhash_pure.meow64(b'hello', 0)
print(f'hello again={h2:#x}')
assert h == h2, "non-deterministic!"
print("import+basic test OK")
