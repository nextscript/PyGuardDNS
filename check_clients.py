import sqlite3
conn = sqlite3.connect('localdnsguard.sqlite3')
conn.row_factory = sqlite3.Row

# Show all clients and their profile assignments
clients = conn.execute('''
    SELECT c.id, c.name, c.ip, c.profile_id, p.name as profile_name
    FROM clients c
    LEFT JOIN profiles p ON c.profile_id = p.id
    ORDER BY c.ip
''').fetchall()
print("=== Clients ===")
for c in clients:
    print(f"  {dict(c)}")

# Show all profiles
profiles = conn.execute('SELECT id, name, safe_search_google, safe_search_bing, safe_search_ddg FROM profiles').fetchall()
print("\n=== Profiles ===")
for p in profiles:
    print(f"  {dict(p)}")
