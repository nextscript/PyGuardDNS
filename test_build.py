"""Test build_filter_engine exactly as app.py does it."""
import sys; sys.path.insert(0, '.')
import os, sqlite3

from dns_engine import FilterEngine
from blocklist_manager import BlocklistManager, fetch_url_text, parse_filter_list, set_dns_resolver
from rules_engine import load_rules_into_engine

# Open the actual database (same as app.py connect_db)
DB_PATH = os.environ.get("LOCALDNSGUARD_DB", "localdnsguard.sqlite3")
conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Same as init_db()
bm = BlocklistManager(conn)
bm.init_schema()

# Same as build_filter_engine()
engine = FilterEngine()
load_rules_into_engine(engine)
bm.load_into_engine(engine)

print(f"Engine loaded: {len(engine.suffix_block)} suffix blocks")

# Test adcrew.co
r = engine.check("adcrew.co")
print(f"adcrew.co: action={r.action}, reason={r.reason}, matched_rule={r.matched_rule}")

# Test a known domain
r2 = engine.check("google.com")
print(f"google.com: action={r2.action}, reason={r2.reason}")

# Check what's in the suffix_block
print(f"adcrew.co in suffix_block: {'adcrew.co' in engine.suffix_block}")

# Check a sample of suffix_block
samples = list(engine.suffix_block)[:5]
print(f"Sample suffix_block entries: {samples}")

conn.close()
