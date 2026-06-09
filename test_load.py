import sys; sys.path.insert(0, '.')
import os, sqlite3
from dns_engine import FilterEngine
from blocklist_manager import BlocklistManager

db_path = os.environ.get('LOCALDNSGUARD_DB', 'localdnsguard.sqlite3')
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

bm = BlocklistManager(conn)
bm.init_schema()

engine = FilterEngine()
bm.load_into_engine(engine)

print('suffix_block has adcrew.co:', 'adcrew.co' in engine.suffix_block)
print('suffix_block size:', len(engine.suffix_block))

r = engine.check('adcrew.co')
print('check action:', r.action)
print('check reason:', r.reason)

row = conn.execute("SELECT value FROM settings WHERE key='filtering_enabled'").fetchone()
print('filtering_enabled setting:', row['value'] if row else 'NOT FOUND')
conn.close()
