from __future__ import annotations

from sqlalchemy import BigInteger, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database.models.base import Base


class Referral(Base):
    __tablename__ = "referrals"

    id: Mapped[str] = mapped_column(primary_key=True)
    owner: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")

    redemptions: Mapped[list[ReferralRedemption]] = relationship(
        back_populates="referral",
        cascade="all, delete-orphan",
        lazy="selectin",
        default_factory=list,
    )


class ReferralRedemption(Base):
    __tablename__ = "referral_redemptions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, init=False)
    referral_id: Mapped[str] = mapped_column(ForeignKey("referrals.id", ondelete="CASCADE"), index=True)
    referred_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0, server_default="0")

    referral: Mapped[Referral | None] = relationship(
        back_populates="redemptions",
        default=None,
        repr=False,
        compare=False,
    )
