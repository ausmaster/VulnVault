class BColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def camel_to_snake(cc_str: str) -> str:
    if not cc_str:
        return ""

    result = [cc_str[0].lower()]
    for char in cc_str[1:]:
        if char.isupper():
            result.append("_")
        result.append(char.lower())

    return "".join(result)


def snake_to_camel(s_str: str) -> str:
    words = s_str.split("_")
    return f"{words[0]}{''.join(word.capitalize() for word in words[1:])}"


def int_to_ordinal(n: int) -> str:
    ordinals = {
        1: "primary",
        2: "secondary",
        3: "tertiary"
    }
    if _ord := ordinals.get(n):
        return _ord

    # Fallback for numbers without specific ordinal names
    # Handling general ordinal numbers (like 4th, 5th, etc.)
    suffix = ["th", "st", "nd", "rd"] + ["th"] * 6  # Suffix list to handle 1st, 2nd, 3rd, 4th, etc.
    v = n % 100
    if 10 <= v <= 20:
        suffix_index = 0  # "th" for 11th to 13th, regardless of the last digit
    else:
        suffix_index = min(n % 10, 4)

    return f"{n}{suffix[suffix_index]}"
