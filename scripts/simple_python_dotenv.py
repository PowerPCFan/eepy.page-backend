"""Please do not remove this header.

Version: 1.0.0 (Released 07 July 2026)
URL: https://github.com/PowerPCFan/simple-python-dotenv
License Text: https://raw.githubusercontent.com/PowerPCFan/simple-python-dotenv/refs/heads/main/LICENSE
"""

# fmt: off

from __future__ import annotations
import codecs
import os
import re
from pathlib import Path
from typing import Union, Optional


def load_dotenv(
    path: Union[str, os.PathLike[str]],
    override_existing: bool = False,
    encoding: Optional[str] = "utf-8",
) -> bool:
    def _removeprefix_if_exists(string: str, prefix: str) -> str:
        if string.startswith(prefix):
            return string[len(prefix):]
        return string

    re1 = re.compile(r"\\[\\']", re.UNICODE)
    re2 = re.compile(r"\\[\\'\"abfnrtv]", re.UNICODE)
    re3 = re.compile(r"\s+#.*", re.UNICODE)
    mapping_dict = {}
    pathlib_path = Path(path)
    if not pathlib_path.is_file():
        return False
    for rline in _removeprefix_if_exists(pathlib_path.read_text(encoding=encoding), "\ufeff").splitlines():
        line = rline.strip()
        if not line or line.startswith("#"):
            continue
        line = _removeprefix_if_exists(line, "export ").lstrip()
        if "=" not in line:
            mapping_dict[line] = None
            continue
        key, value = [ln.strip() for ln in line.split("=", 1)]
        if value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
            value = re1.sub(lambda a: codecs.decode(a.group(0), "unicode-escape"), value)
        elif value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
            value = re2.sub(lambda a: codecs.decode(a.group(0), "unicode-escape"), value)
        else:
            value = re3.sub("", value).rstrip()
        mapping_dict[key] = value
    for k, v in mapping_dict.items():
        if k in os.environ and not override_existing:
            continue
        if v is not None:
            os.environ[k] = v
    return bool(mapping_dict)
