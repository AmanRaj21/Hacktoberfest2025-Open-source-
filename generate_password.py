import secrets
import string
from typing import Optional

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False
) -> str:
    """
    Return a secure random password.

    Args:
        length: total password length (must be >= number of selected classes).
        use_upper/use_lower/use_digits/use_symbols: toggles for character sets.
        avoid_ambiguous: avoids confusing chars like 'l', '1', 'O', '0', etc.

    Raises:
        ValueError if no character classes are selected or length too small.
    """
    # Character sets
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?/~`"  # you can change this

    if avoid_ambiguous:
        ambiguous = "Il1O0"
        upper = "".join(ch for ch in upper if ch not in ambiguous)
        lower = "".join(ch for ch in lower if ch not in ambiguous)
        digits = "".join(ch for ch in digits if ch not in ambiguous)
        symbols = "".join(ch for ch in symbols if ch not in ambiguous)

    pools = []
    if use_upper: pools.append(upper)
    if use_lower: pools.append(lower)
    if use_digits: pools.append(digits)
    if use_symbols: pools.append(symbols)

    if not pools:
        raise ValueError("At least one character class must be enabled.")

    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)} to include one of each selected class.")

    # Ensure at least one char from each class
    password_chars = [secrets.choice(pool) for pool in pools]

    # Fill the rest randomly from the union of pools
    all_chars = "".join(pools)
    password_chars += [secrets.choice(all_chars) for _ in range(length - len(password_chars))]

    # Shuffle securely
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)

# Example usage
if __name__ == "__main__":
    print(generate_password(16))  # default 16-char password
    print(generate_password(12, use_symbols=False))  # no symbols
    print(generate_password(20, avoid_ambiguous=True))  # longer, no ambiguous chars
