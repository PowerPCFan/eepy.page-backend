import logging
import sys
import time

import pytest

from database.tables.domains import Domains
from database.tables.users import Users, UserType
from dns_.dns import sanitize
from dns_.validation import Validation

logger = logging.getLogger(__name__)


class TestDomainValidation:
    def test_valid_name(self) -> None:
        assert Validation.record_name_valid("example-domain.eepy.page", "A")
        assert Validation.record_name_valid("test_dkim.eepy.page", "CNAME")

    def test_valid_subdomain(self) -> None:
        assert Validation.record_name_valid("example.domain.eepy.page", "A")

    def test_invalid_name(self) -> None:
        assert not Validation.record_name_valid("Invälid_Recörd_Nämë.eepy.page", "A")
        assert not Validation.record_name_valid("a..b.eepy.page", "A")
        assert not Validation.record_name_valid("a..eepy.page", "A")
        assert not Validation.record_name_valid("", "A")

    def test_invalid_start_and_end(self) -> None:
        assert not Validation.record_name_valid("example.eepy.page.", "A")
        assert not Validation.record_name_valid(".example.eepy.page", "A")

    def test_txt_record(self) -> None:
        assert Validation.record_name_valid("_verification.eepy.page", "TXT")

    def test_underscore_not_txt_record(self) -> None:
        assert not Validation.record_name_valid("_verification.eepy.page", "A")

    def test_valid_content(self) -> None:
        assert Validation.record_value_valid(["1.2.3.4"], "A")
        assert Validation.record_value_valid(["test.cname.fi."], "CNAME")
        assert Validation.record_value_valid(["test.cname.fi"], "CNAME")

    def test_duplicate_content(self) -> None:
        assert not Validation.record_value_valid(["0.0.0.0", "0.0.0.0"], "A")

    def test_invalid_type(self) -> None:
        assert not Validation.record_value_valid(["0.0.0.0"], "C")
        assert not Validation.record_value_valid(["example.com"], "NS")

    def test_invalid_content_for_type(self) -> None:
        assert not Validation.record_value_valid(["test.cname.fi"], "A")
        assert not Validation.record_value_valid(["0.0.0.0.0.0.0"], "A")
        assert not Validation.record_value_valid(["1500.120.15.2"], "A")
        assert not Validation.record_value_valid(["320.120.15.2"], "A")

    def test_domain_name_conversion(self) -> None:
        assert Domains.canonical_domain_name("a.b") == "a.b"
        assert Domains.canonical_full_domain_name("mysite") == "mysite.eepy.page"
        assert Domains.display_domain_name("a[dot]b") == "a.b"
        assert Domains.legacy_bracket_domain_to_dotted("a[dot]b") == "a.b"

    def test_separation(self) -> None:
        assert Domains.separate_domain_into_parts("test.eepy.page") == (
            "test",
            "eepy.page",
        )

        assert Domains.separate_domain_into_parts("test[dot]eepy[dot]page") == (
            "test",
            "eepy.page",
        )

        assert Domains.separate_domain_into_parts("test.worksonmymachine.top") == (
            "test",
            "worksonmymachine.top",
        )

    def test_sanitization(self) -> None:
        assert sanitize("test.com", "CNAME") == "test.com."
        assert sanitize("test", "TXT") == '"test"'

    def test_reserved_domains(self, validation: Validation) -> None:
        assert Validation.is_reserved_domain("eepy.page")
        assert Validation.is_reserved_domain("api.eepy.page")
        assert Validation.is_reserved_domain("API.eepy.page")
        assert Validation.is_reserved_domain("api.eepy.page.")
        assert Validation.is_reserved_domain("api[dot]eepy[dot]page")
        assert Validation.is_reserved_domain("www.worksonmymachine.top")
        assert Validation.is_reserved_domain("www123.eepy.page")
        assert Validation.is_reserved_domain("_acme-challenge.eepy.page")
        assert not Validation.is_reserved_domain("my-api.eepy.page")
        assert not Validation.is_reserved_domain("www.project.eepy.page")

        assert not validation.is_free("api.eepy.page", "A", {}, raise_exceptions=False)
        assert not validation.is_free("www.worksonmymachine.top", "A", {}, raise_exceptions=False)
        assert not validation.is_free("_acme-challenge.eepy.page", "TXT", {}, raise_exceptions=False)

    def test_admin_can_register_reserved_domain(self, validation: Validation) -> None:
        assert validation.is_free(
            "api.eepy.page",
            "A",
            {},
            user_is_admin=True,
            raise_exceptions=False,
        )


class TestDomainUser:
    def test_register(self, domains: Domains, users: Users, test_user: UserType) -> None:
        domains.add_domain(
            test_user["_id"],
            "TEST.eepy.page",
            {"ip": "1.2.3.4", "registered": round(time.time()), "type": "A"},
        )  # type: ignore
        updated_user_data: UserType | None = users.find_user({"_id": test_user["_id"]})
        if updated_user_data is None:
            pytest.fail("Could not retrieve new user data")

        assert Domains.get_domain(updated_user_data.get("domains", []), "TEST.eepy.page") is not None
        assert Domains.get_domain(updated_user_data.get("domains", []), "test.eepy.page") is not None

        domains.add_domain(
            test_user["_id"],
            "TEST3.eepy.page",
            {"ip": "0.0.0.0", "type": "A", "registered": time.time()},
        )

        updated_user_data = users.find_user({"_id": test_user["_id"]})
        if updated_user_data is None:
            pytest.fail("Could not retrieve new user data")

        assert Domains.get_domain(updated_user_data.get("domains", []), "TEST3.eepy.page") is not None
        assert Domains.get_domain(updated_user_data.get("domains", []), "test3.eepy.page") is not None
        domains.delete_domain(test_user["_id"], "test3.eepy.page")

    def test_multi_type_record_support(self, domains: Domains, users: Users, test_user: UserType) -> None:
        domains.add_domain(
            test_user["_id"],
            "multi-record.eepy.page",
            {"ip": "1.2.3.4", "registered": round(time.time()), "type": "A"},
        )
        domains.add_domain(
            test_user["_id"],
            "multi-record.eepy.page",
            {"ip": "2001:db8::1", "registered": round(time.time()), "type": "AAAA"},
        )

        updated_user_data: UserType | None = users.find_user({"_id": test_user["_id"]})
        if updated_user_data is None:
            pytest.fail("Could not retrieve new user data")

        assert Domains.get_domain(updated_user_data.get("domains", []), "multi-record.eepy.page", "A") is not None
        assert Domains.get_domain(updated_user_data.get("domains", []), "multi-record.eepy.page", "AAAA") is not None
        assert Domains.get_domain(updated_user_data.get("domains", []), "multi-record.eepy.page") is None

        domains.delete_domain(test_user["_id"], "multi-record.eepy.page", "A")
        domains.delete_domain(test_user["_id"], "multi-record.eepy.page", "AAAA")

    def test_cname_conflicts_with_other_record_types(
        self,
        validation: Validation,
        domains: Domains,
        test_user: UserType,
    ) -> None:
        domains.add_domain(
            test_user["_id"],
            "cname-conflict.eepy.page",
            {"ip": "0.0.0.0", "registered": round(time.time()), "type": "A"},
        )

        assert not validation.is_free(
            "cname-conflict.eepy.page",
            "CNAME",
            domains.get_domains(test_user["_id"]),  # pyright: ignore[reportArgumentType]
            user_id=test_user["_id"],
            raise_exceptions=False,
        )

        domains.delete_domain(test_user["_id"], "cname-conflict.eepy.page", "A")

    def test_modify_domain_replaces_original_record(self, domains: Domains, users: Users, test_user: UserType) -> None:
        domains.add_domain(
            test_user["_id"],
            "modified-record.eepy.page",
            {"ip": "0.0.0.0", "registered": round(time.time()), "type": "A"},
        )

        domains.modify_domain(
            test_user["_id"],
            "modified-record.eepy.page",
            value=["target.example.com"],
            type="CNAME",
            old_type="A",
        )

        updated_user_data = users.find_user({"_id": test_user["_id"]})
        if updated_user_data is None:
            pytest.fail("Could not retrieve new user data")

        assert Domains.get_domain(updated_user_data["domains"], "modified-record.eepy.page", "A") is None
        modified_record = Domains.get_domain(updated_user_data["domains"], "modified-record.eepy.page", "CNAME")
        assert modified_record is not None
        assert modified_record["ip"] == ["target.example.com"]

        domains.delete_domain(test_user["_id"], "modified-record.eepy.page", "CNAME")

    def test_modify_domain_updates_matching_type_when_name_has_multiple_records(
        self,
        domains: Domains,
        users: Users,
        test_user: UserType,
    ) -> None:
        domains.add_domain(
            test_user["_id"],
            "multi-modify.eepy.page",
            {"ip": "0.0.0.0", "registered": round(time.time()), "type": "A"},
        )
        domains.add_domain(
            test_user["_id"],
            "multi-modify.eepy.page",
            {"ip": "2001:db8::1", "registered": round(time.time()), "type": "AAAA"},
        )

        domains.modify_domain(
            test_user["_id"],
            "multi-modify.eepy.page",
            value=["target.example.com"],
            type="CNAME",
            old_type="AAAA",
        )

        updated_user_data = users.find_user({"_id": test_user["_id"]})
        if updated_user_data is None:
            pytest.fail("Could not retrieve new user data")

        assert Domains.get_domain(updated_user_data["domains"], "multi-modify.eepy.page", "A") is not None
        assert Domains.get_domain(updated_user_data["domains"], "multi-modify.eepy.page", "AAAA") is None
        assert Domains.get_domain(updated_user_data["domains"], "multi-modify.eepy.page", "CNAME") is not None

        domains.delete_domain(test_user["_id"], "multi-modify.eepy.page", "A")
        domains.delete_domain(test_user["_id"], "multi-modify.eepy.page", "CNAME")

    def test_domain_not_free(self, validation: Validation, domains: Domains) -> None:
        assert not validation.is_free("test.eepy.page", "A", {}, raise_exceptions=False)
        assert not validation.is_free("test.unowned.eepy.page", "A", {}, raise_exceptions=False)
        assert not validation.is_free("test.unowned.eepy.page.", "A", {}, raise_exceptions=False)
        assert not validation.is_free("test.unowned.eepy.page.eepy.page", "A", {}, raise_exceptions=False)

        with pytest.raises(ValueError):
            validation.is_free("testwithouttld", "A", {})

        assert validation.is_free("test20.eepy.page", "A", {}, raise_exceptions=False)

    def test_subtree_and_type_reservation(
        self,
        validation: Validation,
        domains: Domains,
        test_user: UserType,
    ) -> None:
        domains.add_domain(
            test_user["_id"],
            "testing-domains.eepy.page",
            {"ip": "192.168.100.1", "registered": time.time(), "type": "A"},
        )
        user_domains = domains.get_domains(test_user["_id"])

        assert validation.is_free(
            "testing-domains.eepy.page",
            "AAAA",
            user_domains,  # pyright: ignore[reportArgumentType]
            user_id=test_user["_id"],
            raise_exceptions=False,
        )

        assert not validation.is_free(
            "testing-domains.eepy.page",
            "A",
            user_domains,  # pyright: ignore[reportArgumentType]
            user_id=test_user["_id"],
            raise_exceptions=False,
        )

        assert not validation.is_free(
            "child.testing-domains.eepy.page",
            "AAAA",
            {},
            user_id="different-user",
            raise_exceptions=False,
        )

    def test_domain_highest_detection(self, validation: Validation, domains: Domains) -> None:
        assert Validation.find_required_domain("a.b.eepy.page") == "b.eepy.page"
        assert Validation.find_required_domain("a[dot]b[dot]eepy[dot]page") == "b.eepy.page"
        assert Validation.find_required_domain("a.eepy.page") is None
        assert Validation.find_required_domain("a[dot]eepy[dot]page") is None

    def test_domain_limits(self, test_user: UserType, users: Users) -> None:
        # First test the default domain limit
        assert Validation.can_user_register("test2.eepy.page", test_user)[0]
        assert Validation.can_user_register("subdomain.test2.eepy.page", test_user)[0]

        # Change domain limit to be 0. This stops the user from creating new domains, but still allows them to create subdomains
        users.modify_document(
            filter={"_id": test_user["_id"]},
            operation="$set",
            key="permissions.max-domains",
            value=0,
        )

        modified_user = users.find_user({"_id": test_user["_id"]})
        if not modified_user:
            logger.critical("Failed to get testing account")
            sys.exit()

        assert not Validation.can_user_register("test2.eepy.page", modified_user)[0]
        assert Validation.can_user_register("subdomain.test2.eepy.page", modified_user)[0]

        # Disable subdomain registration too
        users.modify_document(
            filter={"_id": test_user["_id"]},
            operation="$set",
            key="permissions.max-subdomains",
            value=0,
        )

        modified_user = users.find_user({"_id": test_user["_id"]})
        if not modified_user:
            logger.critical("Failed to get testing account")
            sys.exit()

        assert not Validation.can_user_register(
            "subdomain.test2.eepy.page",
            modified_user,
        )[0]

        users.modify_document(
            filter={"_id": test_user["_id"]},
            operation="$set",
            key="permissions.max-subdomains",
            value=50,
        )

        users.modify_document(
            filter={"_id": test_user["_id"]},
            operation="$set",
            key="permissions.max-domains",
            value=3,
        )
