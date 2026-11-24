from sqlmodel import SQLModel


class InviteCreate(SQLModel):
    code: str
