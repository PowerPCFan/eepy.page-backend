import json
import logging
import os
from enum import Enum
from typing import Annotated, Any

from fastapi import APIRouter, Form, Request
from fastapi.exceptions import HTTPException

from database.tables.reward_codes import Rewards
from mail.email import Email

logger: logging.Logger = logging.getLogger("eepy.page")


class PurchaseType(Enum):
    DONATION = "Donation"
    SUBSCRIPTION = "Subscription"
    COMMISSION = "Commission"
    SHOP_ORDER = "Shop Order"

    @classmethod
    def from_str(cls, value: str | None) -> "PurchaseType | None":
        value = value.lower() if value else None

        for item in cls:
            if item.value.lower() == value:
                return item

        return None


DOMAIN_LINK_CODES: dict[str, str] = {
    "LINKCODE": "worksonmymachine.top",
}


def add_tld_reward(mapping: dict[str, Any], tld: str) -> None:
    add_to_set = mapping.setdefault("$addToSet", {})
    owned_tlds = add_to_set.setdefault("owned-tlds", {"$each": []})
    owned_tlds["$each"].append(tld)


class Kofi:
    def __init__(self, emails: Email, rewards_table: Rewards) -> None:
        self.router = APIRouter(prefix="/kofi")
        self.emails: Email = emails
        self.rewards: Rewards = rewards_table

        self.router.add_api_route(
            "/webhook",
            self.webhook,
            methods=["POST"],
            responses={
                200: {"description": "Succesfully registered event"},
                401: {"description": "Invalid verification token passed"},
            },
            tags=["kofi"],
        )

        logger.info("Initialized")

    def webhook(self, request: Request, data: Annotated[str, Form()]) -> None:  # noqa: ARG002
        kofi_data: dict[str, Any] = json.loads(data)

        if kofi_data.get("verification_token") != os.environ.get("KOFI_VERIFICATION_TOKEN"):
            logger.warning("Verification code did not match the Ko-fi verification code")
            raise HTTPException(status_code=401, detail="Invalid verification code")

        purchase_type = PurchaseType.from_str(kofi_data.get("type"))

        if purchase_type is None:
            logger.warning("Purchase type not specified")
            raise HTTPException(
                status_code=422,
                detail="Form data did not pass a purchase type",
            )

        email: str | None = kofi_data.get("email")
        if email is None:
            logger.error("Email not specified")
            raise HTTPException(
                status_code=422,
                detail="Form data did not pass an email",
            )

        logger.info("Recieved webhook from Ko-fi")

        mapping: dict[str, Any] = {}

        code: str | None = None

        if purchase_type == PurchaseType.SHOP_ORDER:
            for item in kofi_data.get("shop_items", []):
                item: dict[str, Any]

                direct_link_code = str(item.get("direct_link_code"))
                tld = DOMAIN_LINK_CODES.get(direct_link_code)
                if not tld:
                    logger.warning("Ignoring unknown Ko-fi shop item %s", direct_link_code)
                    continue

                add_tld_reward(mapping, tld)

            if mapping:
                code = self.rewards.create(email, mapping)

        if code is None:
            raise HTTPException(
                status_code=422,
                detail="Invalid purchase type specified",
            )

        self.emails.send_purchase_confirmation(
            email,
            f"https://www.eepy.page/redeem/{code}",
            code,
        )
