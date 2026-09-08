import re, pathlib, json

path = pathlib.Path("tests/test_ro_repo.py")
content = path.read_text()

# We will just rewrite the entire promotion tests manually using string replacement or re.
# Or better, just recreate them correctly.

setup_str = """
    def setup_promo_env(self, risk="normal-app", days_ago=0, pkgs=["ro-control"]):
        out = self.root/"out"
        pub = out/"publication/rpm/fedora/44/beta"
        pub.mkdir(parents=True, exist_ok=True)
        from ro_repo import save
        import datetime as dt
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")
        save(pub/"publication-v1.json", {"schema_version":1,"channel":"beta","snapshot_id":"repo-f44-20260908-001","published_at":past,"publication_run":"test"})
        
        snap = out/"snapshots/fedora/44/repo-f44-20260908-001"
        snap.mkdir(parents=True, exist_ok=True)
        packages = [{"nevra": f"{p}-0:1.0-1.x86_64", "architecture": "x86_64", "filename": f"{p}.rpm", "producer_artifact_sha256": "abc", "published_signed_artifact_sha256": "abc", "producer_manifest_digest": "abc"} for p in pkgs]
        save(snap/"repository-snapshot-v1.json", {"schema_version":1,"snapshot_id":"repo-f44-20260908-001","created_at":"2026-09-08T00:00:00Z","fedora_release":44,"parent_snapshot":None,"packages":packages,"repositories":{},"rpm_signing_fingerprint":"fpr","metadata_signing_fingerprint":"fpr","creation_provenance":{"tool":"test","run":"local"}})
        return out
"""

