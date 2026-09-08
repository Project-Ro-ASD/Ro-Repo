import re
import pathlib

def replace_evidence(text):
    # Match strings inside the evidence lists and replace them with dict structures
    # We will just write a regex or simple text substitution
    def rep(match):
        items_str = match.group(1)
        items = [x.strip().strip('"\'') for x in items_str.split(',') if x.strip()]
        new_items = []
        for i in items:
            new_items.append(f'{{"name":"{i}","result":"pass","snapshot_id":"repo-f44-20260908-001","reference":"http"}}')
        return '"evidence":[' + ','.join(new_items) + ']'
        
    return re.sub(r'"evidence"\s*:\s*\[(.*?)\]', rep, text)

for fname in ["tests/test_ro_repo.py", "tests/e2e-local.sh"]:
    p = pathlib.Path(fname)
    if not p.exists(): continue
    text = p.read_text()
    new_text = replace_evidence(text)
    # also add a fake beta publication for test_promotion_wait_is_enforced
    if fname == "tests/test_ro_repo.py":
        pass
    p.write_text(new_text)

