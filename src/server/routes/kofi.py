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


class LinkCodes(Enum):
    EXTRA_DOMAIN = "65a532e32b"
    ARROVH_SUBDOMAIN = "ee4b5170a6"
    PILLOVH_SUBDOMAIN = "38e30ddc66"
    DOMAIN_BUNDLE = "50a9f34469"


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

    def webhook(self, request: Request, data: Annotated[str, Form()]) -> None:  # noqa: ARG002, C901
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

        mapping: dict = {}

        code: str | None = None

        if purchase_type == "Shop Order":
            for item in kofi_data.get("shop_items", []):
                item: dict[str, Any]

                quantity: int = item.get("quantity", 1)

                match item.get("direct_link_code"):
                    case LinkCodes.EXTRA_DOMAIN:
                        increased_domains = 10 * quantity
                        increased_subdomains = 100 * quantity
                        mapping = {
                            "$inc": {
                                "permissions.max-domains": increased_domains,
                                "permissions.max-subdomains": increased_subdomains,
                            },
                        }
                    case LinkCodes.PILLOVH_SUBDOMAIN:
                        mapping = {"$push": {"owned-tlds": "pill.ovh"}}
                    case LinkCodes.ARROVH_SUBDOMAIN:
                        mapping = {"$push": {"owned-tlds": "arr.ovh"}}
                    case LinkCodes.DOMAIN_BUNDLE:
                        mapping = {
                            "$push": {
                                "owned-tlds": {"$each": ["srvr.be", "pill.ovh", "arr.ovh"]},
                            },
                        }

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
