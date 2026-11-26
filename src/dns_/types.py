from typing import Literal, TypedDict, get_args

AVAILABLE_TLDS = Literal["eepy.page", "worksonmymachine.top"]
TYPES = Literal["A", "AAAA", "CNAME", "TXT"]
ALLOWED_TYPES: list[str] = list(get_args(TYPES))

CHANGE_TYPE = Literal["REPLACE", "DELETE"]


def get_record_type(rec_type: str | TYPES) -> TYPES:
    if rec_type == "A":
        return "A"
    if rec_type == "AAAA":
        return "AAAA"
    if rec_type == "CNAME":
        return "CNAME"
    if rec_type == "TXT":
        return "TXT"
    msg = f"Invalid record type: {rec_type}"
    raise ValueError(msg)


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
