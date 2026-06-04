import sqlite3
conn = sqlite3.connect('localdnsguard.sqlite3')
conn.row_factory = sqlite3.Row
rows = conn.execute('SELECT id, name, safe_search_google, safe_search_bing, safe_search_ddg, youtube_restricted FROM profiles').fetchall()
for r in rows:
    print(dict(r))
