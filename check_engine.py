import sqlite3, sys
sys.path.insert(0, '.')
conn = sqlite3.connect('localdnsguard.sqlite3', check_same_thread=False)
conn.row_factory = sqlite3.Row

from dns_engine import FilterEngine
from client_manager import ClientManager, SAFESEARCH_REWRITES

cm = ClientManager(conn)
engine = FilterEngine()

# Manually run build_filter_engine logic
for profile in cm.get_profiles():
    pid = profile["id"]
    engines_active = []
    if profile.get("safe_search_google"):
        engines_active.append("google")
    if profile.get("safe_search_bing"):
        engines_active.append("bing")
    if profile.get("safe_search_ddg"):
        engines_active.append("ddg")
    engine.set_profile_safesearch(pid, engines_active)
    engine.set_profile_youtube_restricted(pid, bool(profile.get("youtube_restricted")))

print(f"profile_safesearch: {dict(engine.profile_safesearch)}")
print(f"profile_youtube_restricted: {dict(engine.profile_youtube_restricted)}")

# Test
result = engine.check("www.google.com", filtering_enabled=True, profile_id=1)
print(f"www.google.com -> {result.action} {result.answer_ip}")
