import os

path = r'C:\Users\Admin\Documents\soc_ops-main\ml_service\report.py'

with open(path, 'rb') as f:
    content = f.read().decode('utf-8')

# Replace EN DASH (\u2013) and EM DASH (\u2014) with HYPHEN-MINUS (\u002d)
fixed = content.replace('\u2013', '-').replace('\u2014', '-')

if content != fixed:
    print("Found and replaced non-ASCII dashes.")
    with open(path, 'wb') as f:
        f.write(fixed.encode('utf-8'))
else:
    print("No non-ASCII dashes found.")
