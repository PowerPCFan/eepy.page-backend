from typing import Literal, TypedDict, get_args

AVAILABLE_TLDS = Literal["eepy.page", "worksonmymachine.top"]
TYPES = Literal["A", "AAAA", "CNAME", "TXT", "NS"]
ALLOWED_TYPES: list[str] = list(get_args(TYPES))

CHANGE_TYPE = Literal["REPLACE", "DELETE"]


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
