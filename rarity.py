from collections import Counter

def count_same_digits(account_id):
    aid = str(account_id)
    if not aid.isdigit():
        return 0, None
    analyzed = aid[1:] if len(aid) > 1 else aid
    counts = Counter(analyzed)
    if not counts:
        return 0, None
    max_count = max(counts.values())
    for digit, c in counts.items():
        if c == max_count:
            return max_count, digit
    return 0, None

def detect_unik_pattern(account_id):
    aid = str(account_id)
    if not aid.isdigit() or len(aid) < 8:
        return False, None
    for plen in [2, 3, 4]:
        if len(aid) < plen * 3:
            continue
        for start in range(min(3, len(aid) - plen * 2)):
            pat = aid[start:start + plen]
            if len(set(pat)) == 1:
                continue
            rc, pos = 1, start + plen
            while pos + plen <= len(aid):
                if aid[pos:pos + plen] == pat:
                    rc += 1
                    pos += plen
                else:
                    break
            if rc >= 3:
                return True, f"Pattern:{pat}x{rc}"
    if len(aid) >= 7 and aid == aid[::-1]:
        return True, "Palindrome"
    if len(aid) >= 6:
        if all(int(aid[i+1]) - int(aid[i]) == 1 for i in range(len(aid)-1)):
            return True, "Ascending"
        if all(int(aid[i]) - int(aid[i+1]) == 1 for i in range(len(aid)-1)):
            return True, "Descending"
    return False, None

def get_rarity(account_id):
    is_unik, pattern = detect_unik_pattern(account_id)
    if is_unik:
        return "UNIK", pattern
    sc, _ = count_same_digits(account_id)
    if sc >= 11: return "SCARSE+", f"SameDigit:{sc}"
    if sc >= 10: return "SCARSE", f"SameDigit:{sc}"
    if sc >= 9:  return "MYTICH+", f"SameDigit:{sc}"
    if sc >= 8:  return "MYTICH", f"SameDigit:{sc}"
    if sc >= 7:  return "LEGENDARY", f"SameDigit:{sc}"
    if sc >= 6:  return "EPIC", f"SameDigit:{sc}"
    if sc >= 5:  return "RARE+", f"SameDigit:{sc}"
    if sc >= 4:  return "RARE", f"SameDigit:{sc}"
    if sc >= 3:  return "JELEKBET", f"SameDigit:{sc}"
    return "NAJISNYO", f"SameDigit:{sc}"