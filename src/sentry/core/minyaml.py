"""Zero-dependency YAML parser for Sentry configuration files.

Adheres strictly to Python standard library (NFR-3).
Parses a subset of YAML: dicts, lists, scalars (str, int, float, bool, None),
comments (#), and 2-space indentation.
"""

from __future__ import annotations

from typing import Any


def _strip_inline_comment(line: str) -> str:
    """Strip inline comments while respecting quoted strings."""
    in_single = False
    in_double = False
    for i, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line


def _parse_scalar(val: str) -> Any:
    """Parse scalar value to appropriate Python type."""
    val = val.strip()
    if not val:
        return ""

    # Quoted strings
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]

    # Boolean
    lower = val.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False

    # Null
    if lower in ("null", "none", "~", ""):
        return None

    # Integer
    try:
        return int(val)
    except ValueError:
        pass

    # Float
    try:
        return float(val)
    except ValueError:
        pass

    # Default string
    return val


def parse_yaml(text: str) -> dict[str, Any]:
    """Parse a YAML string into a Python dictionary."""
    lines = text.splitlines()
    cleaned_lines: list[tuple[int, str]] = []

    # Filter comments and blank lines, record indentation
    for line in lines:
        stripped = _strip_inline_comment(line)
        if not stripped or stripped.isspace():
            continue
        indent = len(stripped) - len(stripped.lstrip())
        content = stripped.strip()
        if content:
            cleaned_lines.append((indent, content))

    if not cleaned_lines:
        return {}

    def parse_block(index: int, base_indent: int) -> tuple[Any, int]:
        result_dict: dict[str, Any] = {}
        result_list: list[Any] = []
        is_list = False

        while index < len(cleaned_lines):
            indent, content = cleaned_lines[index]

            if indent < base_indent:
                break

            # Handle list items: "- item" or "- key: value"
            if content.startswith("- "):
                is_list = True
                item_content = content[2:].strip()

                if not item_content:
                    # Nested block under list item
                    nested_val, next_idx = parse_block(index + 1, indent + 2)
                    result_list.append(nested_val)
                    index = next_idx
                    continue

                if ":" in item_content:
                    # List of dicts: "- key: value"
                    k, v = item_content.split(":", 1)
                    k = k.strip()
                    v = v.strip()

                    item_dict: dict[str, Any] = {}
                    if v:
                        item_dict[k] = _parse_scalar(v)
                    else:
                        nested_val, next_idx = parse_block(index + 1, indent + 4)
                        item_dict[k] = nested_val
                        index = next_idx

                    # Check for sibling keys under same list item
                    curr_idx = index + 1
                    while curr_idx < len(cleaned_lines):
                        next_indent, next_content = cleaned_lines[curr_idx]
                        if (
                            next_indent == indent + 2
                            and not next_content.startswith("- ")
                            and ":" in next_content
                        ):
                            sk, sv = next_content.split(":", 1)
                            sk = sk.strip()
                            sv = sv.strip()
                            if sv:
                                item_dict[sk] = _parse_scalar(sv)
                                curr_idx += 1
                            else:
                                sub_nested, nxt = parse_block(curr_idx + 1, next_indent + 2)
                                item_dict[sk] = sub_nested
                                curr_idx = nxt
                        else:
                            break
                    index = curr_idx
                    result_list.append(item_dict)
                    continue
                else:
                    result_list.append(_parse_scalar(item_content))
                    index += 1
                    continue

            # Handle key-value pairs: "key: value" or "key:"
            if ":" in content:
                key, val = content.split(":", 1)
                key = key.strip()
                val = val.strip()

                if val:
                    result_dict[key] = _parse_scalar(val)
                    index += 1
                else:
                    # Nested block
                    if index + 1 < len(cleaned_lines):
                        next_indent = cleaned_lines[index + 1][0]
                        if next_indent > indent:
                            nested_val, next_idx = parse_block(index + 1, next_indent)
                            result_dict[key] = nested_val
                            index = next_idx
                        else:
                            result_dict[key] = None
                            index += 1
                    else:
                        result_dict[key] = None
                        index += 1
            else:
                index += 1

        return (result_list if is_list else result_dict), index

    result, _ = parse_block(0, 0)
    return result if isinstance(result, dict) else {"items": result}


def load_yaml_file(filepath: str) -> dict[str, Any]:
    """Load and parse a YAML file from disk."""
    with open(filepath, encoding="utf-8") as f:
        return parse_yaml(f.read())
