import re


def mask_secret(value: str) -> str:
    """
    Masks a sensitive string so that the raw secret is never stored or displayed.
    Never returns the complete secret under any circumstances.
    """
    if not value:
        return "********"

    clean_val = value.strip()

    # Special handling for PEM private keys
    if "-----BEGIN" in clean_val:
        header_match = re.search(r"-----BEGIN [A-Z0-9 ]+-----", clean_val)
        footer_match = re.search(r"-----END [A-Z0-9 ]+-----", clean_val)
        header = header_match.group(0) if header_match else "-----BEGIN PRIVATE KEY-----"
        footer = footer_match.group(0) if footer_match else "-----END PRIVATE KEY-----"
        return f"{header} ... [MASKED KEY MATERIAL] ... {footer}"

    length = len(clean_val)
    if length <= 4:
        return "********"
    elif length <= 8:
        # Show first 1 and last 1
        return f"{clean_val[0]}****{clean_val[-1]}"
    elif length <= 16:
        # Show first 2 and last 2
        return f"{clean_val[:2]}****{clean_val[-2:]}"
    else:
        # Show first 4 and last 4
        return f"{clean_val[:4]}****{clean_val[-4:]}"

