import re
with open('app.py', 'r') as f:
    lines = f.readlines()
for i, line in enumerate(lines, 1):
    stripped = line.strip()
    # Check for f-string with conditional containing nested f-string
    if '{f"' in stripped or "{f'" in stripped or '{f""' in stripped:
        print(f'Line {i}: potentially nested f-string expr: {stripped[:150]}')
    # Check for backslash in f-string contexts
    if 'f"' in stripped and '\\"' in stripped.replace("f'", ''):
        print(f'Line {i}: possible backslash in f-string: {stripped[:150]}')
