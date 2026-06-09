import sys; sys.path.insert(0, '.')
import sqlite3
conn = sqlite3.connect('localdnsguard.sqlite3')
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT value FROM settings WHERE key='query_log_enabled'").fetchone()
print('query_log_enabled:', row['value'] if row else 'NOT FOUND')
rows = conn.execute('SELECT id, name, enabled FROM blocklists').fetchall()
for r in rows:
    print(f'BL: id={r["id"]}, name={r["name"]}, enabled={r["enabled"]}')
conn.close()
