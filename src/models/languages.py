from sqlmodel import SQLModel


class ContributionBody(SQLModel):
    keys: list[dict[str, str]]
