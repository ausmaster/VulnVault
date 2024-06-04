"""
Provides utility classes, functions for the other files.
"""
from functools import partial

s_print = partial(print, end=" ")


class BColors:
    """
    Provide list of console colors.
    """
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    @classmethod
    def success_msg(cls, msg: str) -> str:
        """
        Provides a console green success message.

        :param msg: Message to turn green.
        :return: A greenified message.
        """
        return f"{cls.OKGREEN}{msg}{cls.ENDC}"

    @classmethod
    def fail_msg(cls, msg: str) -> str:
        """
        Provides a console red fail message.

        :param msg: Message to turn red.
        :return: A red message.
        """
        return f"{cls.FAIL}{msg}{cls.ENDC}"

    @classmethod
    def underline_msg(cls, msg: str) -> str:
        """
        Provides a console underlined message.

        :param msg: Message to underline.
        :return: An underlined message.
        """
        return f"{cls.UNDERLINE}{msg}{cls.ENDC}"

    @classmethod
    def print_success(cls, msg: str, **kwargs) -> None:
        """
        Prints to console a green success message.

        :param msg: Message to turn green and print.
        :return: None
        """
        print(cls.success_msg(msg), **kwargs)

    @classmethod
    def print_fail(cls, msg: str, **kwargs) -> None:
        """
        Prints to console a red fail message.

        :param msg: Message to turn red and print.
        :return: None
        """
        print(cls.fail_msg(msg), **kwargs)

    @classmethod
    def print_underline(cls, msg: str, **kwargs) -> None:
        """
        Prints to console a underlined message.

        :param msg: Message to underline and print.
        :return: None
        """
        print(cls.underline_msg(msg), **kwargs)


def camel_to_snake(cc_str: str) -> str:
    """
    Converts a camelCase string to snake_case.

    :param cc_str: camelCase string to convert.
    :return: snake_cased string.
    """
    if not cc_str:
        return ""

    result = [cc_str[0].lower()]
    for char in cc_str[1:]:
        if char.isupper():
            result.append("_")
        result.append(char.lower())

    return "".join(result)


def snake_to_camel(s_str: str) -> str:
    """
    Converts a snake_case string to camelCase.
    :param s_str: snake_case string to convert.
    :return: camelCased string.
    """
    words = s_str.split("_")
    return f"{words[0]}{''.join(word.capitalize() for word in words[1:])}"


def int_to_ordinal(n: int) -> str:
    """
    Converts an integer to an ordinal string.
    :param n: Integer to convert.
    :return: Ordinal string.
    """
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
