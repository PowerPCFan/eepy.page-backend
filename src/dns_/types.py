from typing import Literal, TypedDict, get_args

AVAILABLE_TLDS = Literal["eepy.page", "worksonmymachine.top"]
TYPES = Literal["A", "AAAA", "CNAME", "TXT"]
ALLOWED_TYPES: list[str] = list(get_args(TYPES))

CHANGE_TYPE = Literal["REPLACE", "DELETE"]


def get_rec_type(type_: str | TYPES) -> TYPES:
    if type_ not in {"A", "AAAA", "CNAME", "TXT"}:
        msg = f"Invalid record type: {type_}"
        raise ValueError(msg)
    return type_  # pyright: ignore[reportReturnType]


class Record(TypedDict):
    content: str
    disabled: bool
    comment: str


class RRSet(TypedDict):
    name: str
    type: TYPES
    ttl: int
    changetype: CHANGE_TYPE
    records: list[Record]
