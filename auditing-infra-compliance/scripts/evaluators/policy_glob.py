"""IAM-style wildcard matching (`*` = any run of characters, `?` = any one character) for policy text that comes from the audited account.

Policy patterns are attacker-controlled input here (anyone who can write a bucket policy chooses them), so they are never turned
into a regular expression: `a*a*a*a*...Z` as a regex backtracks exponentially. This matcher is a bit-parallel NFA: one big-integer
state set per pattern, one step per character of the text, so the cost is O(len(text) * len(pattern) / word size) whatever the pattern.
"""


def glob_match(pattern: str, text: str, *, ignore_case: bool = False) -> bool:
    """True when the whole of `text` matches `pattern`. Only `*` and `?` are special; every other character matches itself."""
    if ignore_case:
        pattern, text = pattern.lower(), text.lower()
    literal: dict[str, int] = {}  # character -> states (tokens before it already matched) that this character advances
    star = any_char = state = 0
    for token in pattern:
        if token == "*":
            star |= 1 << state  # a star is a loop on the state between two tokens, so runs of stars collapse by themselves
            continue
        if token == "?":
            any_char |= 1 << state
        else:
            literal[token] = literal.get(token, 0) | (1 << state)
        state += 1
    final = 1 << state
    current = 1
    for char in text:
        current = (((current & (literal.get(char, 0) | any_char)) << 1) | (current & star))
        if not current:
            return False
    return bool(current & final)
