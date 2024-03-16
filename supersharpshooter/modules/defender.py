#!/usr/bin/python
import random
import re
from typing import List


def concat_rand(input_string: str, language: str) -> str:
    """
    Enhances string obfuscation by splitting the input string into random-sized
    chunks and concatenating them with varying delimiters based on the language.

    Args:
        input_string (str): The string to be obfuscated.
        language (str): The target programming language for obfuscation.

    Returns:
        str: The obfuscated string with language-specific concatenations.
    """

    def generate_chunks(string: str) -> List[str]:
        chunks = []
        while string:
            chunk_size = random.randint(1, max(2, len(string) // 3))
            chunks.append(string[:chunk_size])
            string = string[chunk_size:]
        return chunks

    chunks = generate_chunks(input_string)

    if language == "js":
        delimiters = ["+", "'+'", "'.'"]
        return "".join(f"'{chunk}'{random.choice(delimiters)}" for chunk in chunks)[
            : -len(random.choice(delimiters))
        ]
    elif language in ["vba", "vbs"]:
        return " & ".join(f'"{chunk}"' for chunk in chunks)


# Enhanced fix_hardcode function using the enhanced concat_rand
def fix_hardcode(base: str, language: str, target_string: str = "SharpShooter") -> str:
    """
    Replaces a specific hardcoded string in the base string with an obfuscated
    version to evade signature-based detection.

    Args:
        base (str): The original string.
        language (str): The programming language for obfuscation.
        target_string (str): The string to obfuscate.

    Returns:
        str: The string with obfuscated replacements.
    """
    obfuscated_string = concat_rand(target_string, language)
    return base.replace(target_string, obfuscated_string)
