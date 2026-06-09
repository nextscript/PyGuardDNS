import sys; sys.path.insert(0, '.')
import sqlite3
conn = sqlite3.connect('localdnsguard.sqlite3')
conn.row_factory = sqlite3.Row
# Check custom rules table
rows = conn.execute("SELECT * FROM rules WHERE pattern LIKE '%adcrew%'").fetchall()
for r in rows:
    print('Custom rule:', dict(r))
# Check profile_custom_rules
try:
    rows = conn.execute("SELECT * FROM profile_custom_rules WHERE pattern LIKE '%adcrew%'").fetchall()
    for r in rows:
        print('Profile custom rule:', dict(r))
except Exception as e:
    print('profile_custom_rules error:', e)
# Check profiles
rows = conn.execute("SELECT id, name, filtering_enabled FROM profiles").fetchall()
for r in rows:
    print('Profile:', dict(r))
conn.close()
