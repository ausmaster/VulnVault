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
    words = s_str.split('_')
    return words[0] + "".join(word.capitalize() for word in words[1:])