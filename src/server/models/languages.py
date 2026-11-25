from pydantic import BaseModel


class ContributionBody(BaseModel):
    keys: list[dict[str, str]]
