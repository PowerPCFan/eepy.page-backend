import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

import resend
import resend.exceptions

from security.encryption import Encryption

if TYPE_CHECKING:
    from database.tables.codes import Codes
    from database.tables.users import Users, UserType


template_path: Path = Path("src") / "mail" / "templates"

verify_template: str
recovery_template: str
deletion_template: str
banned_template: str
domain_delete_template: str
purchase_template: str
admin_template: str

with (template_path / "verify.html").open() as f:
    verify_template = "\n".join(f.readlines())

with (template_path / "deletion.html").open() as f:
    deletion_template = "\n".join(f.readlines())

with (template_path / "recovery.html").open() as f:
    recovery_template = "\n".join(f.readlines())

with (template_path / "banned.html").open() as f:
    banned_template = "\n".join(f.readlines())

with (template_path / "domain_removal.html").open() as f:
    domain_delete_template = "\n".join(f.readlines())

with (template_path / "purchase.html").open() as f:
    purchase_template = "\n".join(f.readlines())

with (template_path / "admin_action.html").open() as f:
    admin_template = "\n".join(f.readlines())

logger: logging.Logger = logging.getLogger("eepy.page")


class Email:
    def __init__(self, codes: "Codes", users: "Users", encryption: Encryption) -> None:
        self.codes: Codes = codes
        self.users: Users = users
        self.encryption: Encryption = encryption  # type: ignore[arg-type]
        resend.api_key = os.getenv("RESEND_KEY")

    def is_taken(self, email: str) -> bool:
        replaced_email: str = email.replace(
            "+",
            "@",
        )  # removes ability to make alt accounts using the same email (ex. a@gmail.com, a+hi@gmail.com)
        email_parts: list[str] = replaced_email.split("@")
        processed_email = f"{email_parts[0]}@{email_parts[-1]}"

        email_hash: str = Encryption.sha256(processed_email + "supahcool")

        return self.users.find_item({"email-hash": email_hash}) is not None

    def send_verification_code(self, base_url: str, username: str, email: str) -> bool:
        code: str = self.codes.create_code("verification", username)
        try:
            resend.Emails.send(
                {
                    "from": "noreply@mail.eepy.page",
                    "to": email,
                    "subject": "Verify your account",
                    "html": verify_template.replace(
                        "{{link}}",
                        f"{base_url}/account/verify/email?code={code}",
                    ),
                    "text": f"Go to {base_url}/account/verify/email?code={code} to verify your account",
                },
            )
        except resend.exceptions.ResendError:
            logger.exception("Failed to send verification code:")
            return False
        return True

    def send_purchase_confirmation(
        self,
        email: str,
        purchase_link: str,
        code: str,
    ) -> bool:
        try:
            resend.Emails.send(
                {
                    "from": "noreply@mail.eepy.page",
                    "to": email,
                    "subject": "Order completed",
                    "html": purchase_template.replace(
                        "{{link}}",
                        purchase_link,
                    ).replace("{{code}}", code),
                    "text": f"To activate your product, go to {purchase_link}",
                },
            )
        except resend.exceptions.ResendError:
            logger.exception("Failed to purchase code:")
            return False
        return True

    def send_delete_code(self, base_url: str, username: str, email: str) -> bool:
        code: str = self.codes.create_code("deletion", username)
        url = base_url + f"/account/verify/deletion?code={code}"
        try:
            resend.Emails.send(
                {
                    "from": "noreply@mail.eepy.page",
                    "to": email,
                    "subject": "Account deletion",
                    "html": deletion_template.replace("{{link}}", url),
                    "text": f"Go to {url} to delete your account",
                },
            )

        except resend.exceptions.ResendError:
            logger.exception("Failed to send verification code:")
            return False

        logger.info(f"Sent account deletion code to username {username}")
        return True

    def send_password_code(self, username: str) -> bool:
        hash_username: str = Encryption.sha256(username)
        user_data: UserType | None = self.users.find_user({"_id": hash_username})

        if user_data is None:
            logger.debug(f"User {username} does not exist")
            return False

        user_email = self.encryption.decrypt(user_data["email"])
        code = self.codes.create_code("recovery", hash_username)

        try:
            resend.Emails.send(
                {
                    "from": "noreply@mail.eepy.page",
                    "to": user_email,
                    "subject": "Password recovery",
                    "html": recovery_template.replace(
                        "{{link}}",
                        f"https://www.eepy.page/account/recover?c={code}",
                    ),
                },
            )
        except resend.exceptions.ResendError:
            logger.exception("Failed to send verification code:")
            return False

        logger.info(f"Sent password reset code to username {username}")
        return True

    def send_ban_email(self, target_email: str, reasons: list[str]) -> bool | None:
        reasons_html = ""
        for reason in reasons:
            reasons_html += f"<li>{reason}</li>"

        try:
            resend.Emails.send(
                {
                    "from": "noreply@mail.eepy.page",
                    "to": target_email,
                    "subject": "Account termination",
                    "html": banned_template.replace("{{reasons}}", reasons_html),
                },
            )
        except resend.exceptions.ResendError as e:
            logger.exception(f"Failed to send ban email {e.suggested_action}")
            return False

    def send_domain_termination_email(
        self,
        target_email: str,
        domain: str,
        reason: str,
    ) -> bool | None:
        """
        Sends an email to the user that one of their domains have been deleted

        domain should be the domain without the eepy.page suffix
        """

        try:
            resend.Emails.send(
                {
                    "from": "noreply@mail.eepy.page",
                    "to": target_email,
                    "subject": "Domain removed",
                    "html": domain_delete_template.replace(
                        "{{reason}}",
                        reason,
                    ).replace("{{domain}}", domain),
                },
            )
        except resend.exceptions.ResendError as e:
            logger.exception(f"Failed to send domain email {e.suggested_action}")
            return False

    def send_admin_email(self, target_email: str, action: str) -> bool | None:
        try:
            resend.Emails.send(
                {
                    "from": "noreply@mail.eepy.page",
                    "to": target_email,
                    "subject": "An action on your account",
                    "html": admin_template.replace("{{action}}", action),
                },
            )
        except resend.exceptions.ResendError as e:
            logger.exception(f"Failed to send domain email {e.suggested_action}")
            return False
