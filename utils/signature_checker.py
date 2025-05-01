# File: utils/signature_checker.py

import yara

def match_signatures(rules: yara.Rules, filepath: str) -> bool:
    try:
        matches = rules.match(filepath)
        return len(matches) > 0
    except Exception:
        return False
