#!/usr/bin/env python3

import glob
import os

from typing import Sequence


def tab(n: int) -> int:
    """
    What's the next index of a simulated tab.
    """
    a = (n + 3) // 4 * 4
    return a + 4 if a == n else a


def inject_string_at_index(line: str, to_inject: str, index: int) -> str:
    """
    Inject a string at a specific index.
    """
    return line[:index] + to_inject + line[index:]


def delete_chars_at_index(line: str, n: int, index: int) -> str:
    """
    Delete characters at a specific index.
    """
    return line[:index] + line[index + n:]


def find_space_after(line: str, start_index: int) -> int:
    """
    Find the first space after some index.
    """
    for index, c in enumerate(line[start_index:]):
        if c == " ":
            return index + start_index
    return -1


def next_word_index(line: str, start_index: int) -> int:
    """
    Find the next word. Assumes start index is not a space.
    """
    space_index = line.find(" ", start_index)
    if space_index == -1:
        raise Exception(f"missing param documentation: {repr(line)}")

    # Find the first non-space character after the space
    non_space_index = space_index + 1
    while non_space_index < len(line) and line[non_space_index] == " ":
        non_space_index += 1
    assert non_space_index < len(line)
    return non_space_index


def format_param_lines(lines: Sequence[str]) -> Sequence[str]:
    """
    Given some lines with @param, properly format them.
    """
    valid_var_index = 0
    for line in lines:
        index = find_space_after(line, line.find("@param"))
        valid_var_index = max(valid_var_index, tab(index))

    new_lines = []
    for line in lines:
        var_index = next_word_index(line, line.find('@param'))
        if var_index > valid_var_index:
            spaces_to_delete = var_index - valid_var_index
            line = delete_chars_at_index(line, spaces_to_delete, var_index - spaces_to_delete)
        if var_index < valid_var_index:
            spaces_to_add = valid_var_index - var_index
            line = inject_string_at_index(line, " " * spaces_to_add, var_index)
        new_lines.append(line)

    lines = new_lines
    valid_desc_index = 0
    for line in lines:
        index = find_space_after(line, valid_var_index)
        valid_desc_index = max(valid_desc_index, tab(index))

    new_lines = []
    for line in lines:
        desc_index = next_word_index(line, valid_var_index)
        if desc_index > valid_desc_index:
            spaces_to_delete = desc_index - valid_desc_index
            line = delete_chars_at_index(line, spaces_to_delete, desc_index - spaces_to_delete)
        if desc_index < valid_desc_index:
            spaces_to_add = valid_desc_index - desc_index
            line = inject_string_at_index(line, " " * spaces_to_add, desc_index)
        new_lines.append(line)

    return new_lines


def format_params(file_path: str):
    """
    Given some file, format all of the @param lines.
    """
    with open(file_path, "r") as file:
        lines = file.readlines()

    param_lines = []
    modified_lines = []
    for line in lines:
        if "@param" in line:
            param_lines.append(line)
        else:
            if len(param_lines) != 0:
                new_lines = format_param_lines(param_lines)
                modified_lines.extend(new_lines)
            modified_lines.append(line)
            param_lines = []

    with open(file_path, "w") as file:
        file.writelines(modified_lines)


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(script_dir, "../src")

    src_files = []
    src_files += glob.glob(os.path.join(src_dir, "**", "*.c"), recursive=True)
    src_files += glob.glob(os.path.join(src_dir, "**", "*.h"), recursive=True)

    for f in src_files:
        format_params(f)
