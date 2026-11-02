# ruff: noqa: PLR2004, C901, PLR0911, PLR0912

import logging
import re
import string
from typing import TYPE_CHECKING, NamedTuple, get_args

from database.exceptions import SubdomainError, UserNotExistError
from database.tables.domains import DomainFormat, Domains
from database.tables.users import UserType
from dns_.exceptions import DNSException, DomainExistsError, ReservedDomainError
from dns_.types import ALLOWED_TYPES, AVAILABLE_TLDS
from security.admin_permissions import get_account_limits

if TYPE_CHECKING:
    from dns_.dns import DNS

logger: logging.Logger = logging.getLogger("eepy.page")


class UserCanRegisterResult(NamedTuple):
    success: bool
    comment: str


GITHUB_LIST: set[str] = {
    "21cf",
    "3m",
    "53",
    "a",
    "aa",
    "abbott",
    "abbvie",
    "abm",
    "about",
    "aboutmcdonalds",
    "aboutschwab",
    "abuse",
    "access",
    "account",
    "accounts",
    "ad",
    "adm",
    "admin",
    "administrator",
    "administrators",
    "adp",
    "ads",
    "adserver",
    "adv",
    "advanceautoparts",
    "aecom",
    "aep",
    "aes",
    "aetna",
    "affiliate",
    "affiliates",
    "afginc",
    "aflac",
    "agcocorp",
    "agenda",
    "aig",
    "airgas",
    "airproducts",
    "ajg",
    "aksteel",
    "alaskaair",
    "alcoa",
    "alliancedata",
    "allstate",
    "ally",
    "alpha",
    "altria",
    "amark",
    "amazon",
    "ameren",
    "americanexpress",
    "ameriprise",
    "amerisourcebergen",
    "amfam",
    "amgen",
    "amphenol",
    "anadarko",
    "analytics",
    "anixter",
    "antheminc",
    "apachecorp",
    "api",
    "app",
    "apple",
    "appliedmaterials",
    "apps",
    "aramark",
    "archive",
    "arrow",
    "asburyauto",
    "ashland",
    "asset",
    "assets",
    "assurant",
    "atom",
    "att",
    "auth",
    "auto",
    "auto-owners",
    "autoconfig",
    "autodiscover",
    "autoliv",
    "autonation",
    "autozone",
    "averydennison",
    "avisbudgetgroup",
    "avnet",
    "avoncompany",
    "b",
    "b2b",
    "backup",
    "backups",
    "bakerhughes",
    "ball",
    "bankofamerica",
    "barnesandnobleinc",
    "baxalta",
    "baxter",
    "bb",
    "bbs",
    "bbt",
    "bd",
    "bedbathandbeyond",
    "berkshirehathaway",
    "bestbuy",
    "beta",
    "biglots",
    "billing",
    "biogen",
    "blackrock",
    "blog",
    "blogs",
    "bms",
    "bnymellon",
    "board",
    "boeing",
    "book",
    "bookmark",
    "bookmarks",
    "boozallen",
    "borgwarner",
    "bostonscientific",
    "bot",
    "bots",
    "broadcast-ip",
    "broadcom",
    "bug",
    "bugs",
    "burlingtonstores",
    "business",
    "c",
    "c-a-m",
    "cablevision",
    "cache",
    "cal",
    "calendar",
    "calpine",
    "campbellsoupcompany",
    "capitalone",
    "cardinal",
    "careers",
    "carmax",
    "caseys",
    "caterpillar",
    "cbrands",
    "cbre",
    "cbscorporation",
    "cdn",
    "cdw",
    "celanese",
    "celgene",
    "centene",
    "centerpointenergy",
    "centurylink",
    "ch2m",
    "charter",
    "chat",
    "chevron",
    "chk",
    "chrobinson",
    "chs",
    "chsinc",
    "cigna",
    "cinfin",
    "cisco",
    "citigroup",
    "citizensbank",
    "citrix",
    "client",
    "clients",
    "cloud",
    "cmc",
    "cms",
    "cmsenergy",
    "cn",
    "coca-colacompany",
    "code",
    "cognizant",
    "cokecce",
    "colgatepalmolive",
    "comcastcorporation",
    "comment",
    "comments",
    "communities",
    "community",
    "conagrafoods",
    "conedison",
    "connect",
    "conocophillips",
    "contact",
    "content",
    "contributors",
    "control",
    "coppa",
    "copyright",
    "core-mark",
    "corning",
    "corp",
    "costco",
    "cp",
    "cpanel",
    "create",
    "crm",
    "crowncork",
    "csc",
    "css",
    "cssproxy",
    "cstbrands",
    "csx",
    "cummins",
    "customize",
    "cvs",
    "cvshealth",
    "d",
    "dana",
    "danaher",
    "darden",
    "dashboard",
    "data",
    "davita",
    "db",
    "dbadmin",
    "dc",
    "de",
    "deanfoods",
    "delekus",
    "delete",
    "delta",
    "demo",
    "design",
    "destroy",
    "dev",
    "devel",
    "develop",
    "developer",
    "developers",
    "development",
    "devonenergy",
    "dickssportinggoods",
    "dillards",
    "direct",
    "directory",
    "discoverfinancial",
    "discoverycommunications",
    "dish",
    "disney",
    "diversity",
    "dmca",
    "dns",
    "doc",
    "docs",
    "dollargeneral",
    "dollartree",
    "dom",
    "domain",
    "domains",
    "domtar",
    "dovercorporation",
    "dow",
    "download",
    "downloads",
    "drhorton",
    "drpeppersnapplegroup",
    "drupal",
    "dteenergy",
    "duke-energy",
    "dupont",
    "e",
    "e-mail",
    "eastman",
    "ebay",
    "ecolab",
    "edisoninvestor",
    "edit",
    "edu",
    "edwardjones",
    "elcompanies",
    "email",
    "embed",
    "embedded",
    "emc",
    "emcorgroup",
    "emerson",
    "en",
    "energyfutureholdings",
    "energytransfer",
    "eng",
    "english",
    "entergy",
    "enterpriseproducts",
    "eogresources",
    "erieinsurance",
    "es",
    "essendant",
    "event",
    "events",
    "eversource",
    "evhc",
    "example",
    "exchange",
    "exeloncorp",
    "expediainc",
    "expeditors",
    "explore",
    "express-scripts",
    "extranet",
    "exxonmobil",
    "f",
    "facebook",
    "fanniemae",
    "faq",
    "faqs",
    "farmers",
    "favorite",
    "favorites",
    "fax",
    "fb",
    "fcx",
    "fedex",
    "feed",
    "feedback",
    "feeds",
    "file",
    "files",
    "finance",
    "firewall",
    "firstam",
    "firstdata",
    "firstenergycorp",
    "fiserv",
    "fisglobal",
    "fluor",
    "fmctechnologies",
    "fnf",
    "footlocker-inc",
    "ford",
    "forms",
    "forum",
    "forums",
    "foto",
    "fr",
    "franklinresources",
    "freddiemac",
    "free",
    "friend",
    "friends",
    "frontier",
    "fs",
    "ftp",
    "fw",
    "g",
    "gallery",
    "game",
    "games",
    "gamestopcorp",
    "gapinc",
    "gate",
    "gateway",
    "ge",
    "general",
    "generaldynamics",
    "generalmills",
    "genesishcc",
    "genpt",
    "genworth",
    "get",
    "gift",
    "gilead",
    "gis",
    "git",
    "globalp",
    "gm",
    "gmail",
    "go",
    "goodyear",
    "google",
    "gov",
    "grainger",
    "graybar",
    "group1auto",
    "groups",
    "gs",
    "guardianlife",
    "guide",
    "guides",
    "halliburton",
    "hanes",
    "harley-davidson",
    "harman",
    "hcahealthcare",
    "hdsupply",
    "healthnet",
    "help",
    "henryschein",
    "hertz",
    "hess",
    "hiltonworldwide",
    "hollyfrontier",
    "home",
    "homedepot",
    "honeywell",
    "hormelfoods",
    "host",
    "hosthotels",
    "hosting",
    "hostmaster",
    "hp",
    "hr",
    "hrggroup",
    "html",
    "humana",
    "huntingtoningalls",
    "huntsman",
    "i",
    "ibm",
    "icon",
    "icons",
    "id",
    "identity",
    "idp",
    "ielp",
    "iheartmedia",
    "im",
    "image",
    "images",
    "imap",
    "img",
    "in",
    "inbox",
    "index",
    "info",
    "ingrammicro",
    "ingredion",
    "insight",
    "intel",
    "internationalpaper",
    "interpublic",
    "intlfcstone",
    "intra",
    "intranet",
    "invite",
    "ip",
    "ipfixe",
    "iphone",
    "ipv4",
    "irc",
    "it",
    "itw",
    "jabber",
    "jabil",
    "jacobs",
    "jarden",
    "jbhunt",
    "jcpenney",
    "jetblue",
    "jll",
    "jmsmucker",
    "jnj",
    "job",
    "jobs",
    "johndeere",
    "johnsoncontrols",
    "jp",
    "jpmorganchase",
    "js",
    "kb",
    "kelloggcompany",
    "kellyservices",
    "kiewit",
    "kimberly-clark",
    "kindermorgan",
    "kindredhealthcare",
    "kkr",
    "knowledgebase",
    "kohlscorporation",
    "kraftheinzcompany",
    "l-3com",
    "lab",
    "labcorp",
    "labs",
    "lamresearch",
    "landolakesinc",
    "lansingtradegroup",
    "lb",
    "ldap",
    "lear",
    "legacy",
    "legal",
    "lennar",
    "leucadia",
    "level3",
    "lfg",
    "lib",
    "libertyinteractive",
    "libertymutual",
    "library",
    "libs",
    "lifepointhealth",
    "lilly",
    "link",
    "links",
    "linux",
    "list",
    "lists",
    "lithia",
    "live",
    "livenation",
    "lkqcorp",
    "lms",
    "local",
    "localhost",
    "lockheedmartin",
    "loews",
    "loghost",
    "login",
    "loopback",
    "lowes",
    "m",
    "macysinc",
    "mail",
    "mailadmin",
    "mailer",
    "mailhost",
    "mailing",
    "mailman",
    "mailserver",
    "main",
    "manage",
    "manpowergroup",
    "map",
    "maps",
    "marathonoil",
    "marathonpetroleum",
    "markelcorp",
    "market",
    "marketing",
    "marriott",
    "masco",
    "massmutual",
    "master",
    "mastercard",
    "mattel",
    "mckesson",
    "media",
    "member",
    "members",
    "merck",
    "messages",
    "metlife",
    "mgmresorts",
    "micron",
    "microsoft",
    "mirror",
    "mmc",
    "mobile",
    "mohawkind",
    "molinahealthcare",
    "mondelezinternational",
    "monitor",
    "monitoring",
    "monsanto",
    "moodle",
    "morganstanley",
    "mosaicco",
    "motorolasolutions",
    "mrtg",
    "ms",
    "mssql",
    "murphyusa",
    "mutualofomaha",
    "mx",
    "my",
    "mysql",
    "nagios",
    "nationwide",
    "navient",
    "navistar",
    "ncr",
    "net",
    "netapp",
    "netflix",
    "network-ip",
    "new",
    "newellbrands",
    "newmont",
    "news",
    "newscorp",
    "newsletter",
    "newyorklife",
    "nexteraenergy",
    "nglenergypartners",
    "nike",
    "nisource",
    "nl",
    "noc",
    "nordstrom",
    "northropgrumman",
    "northwesternmutual",
    "nov",
    "nrgenergy",
    "ns",
    "nscorp",
    "ntp",
    "ntp1",
    "nucor",
    "nvrinc",
    "o-i",
    "oa",
    "office",
    "officedepot",
    "official",
    "old",
    "oldmail",
    "oldrepublic",
    "omnicomgroup",
    "oneok",
    "online",
    "oracle",
    "oreillyauto",
    "origin",
    "oshkoshcorporation",
    "outlook",
    "owa",
    "owens-minor",
    "owenscorning",
    "oxy",
    "p",
    "paccar",
    "pacificlife",
    "packagingcorp",
    "pages",
    "paid",
    "panel",
    "parker",
    "partner",
    "partners",
    "pay",
    "payment",
    "payments",
    "paypal",
    "pbfenergy",
    "pbx",
    "pda",
    "peabodyenergy",
    "penskeautomotive",
    "pepsico",
    "pfgc",
    "pfizer",
    "pg",
    "pge",
    "pgsql",
    "phillips66",
    "photo",
    "photos",
    "php",
    "phpmyadmin",
    "pics",
    "picture",
    "pictures",
    "plainsallamerican",
    "pm",
    "pmi",
    "pnc",
    "policy",
    "pop",
    "pop3",
    "portal",
    "post",
    "postmaster",
    "ppg",
    "pplweb",
    "pr",
    "praxair",
    "precast",
    "press",
    "preview",
    "pricelinegroup",
    "principal",
    "privacy",
    "private",
    "pro",
    "prod",
    "product",
    "production",
    "products",
    "profile",
    "progressive",
    "project",
    "projects",
    "promo",
    "proxy",
    "prudential",
    "pseg",
    "pt",
    "public",
    "publix",
    "pultegroupinc",
    "purge",
    "put",
    "pvh",
    "qa",
    "qualcomm",
    "quantaservices",
    "questdiagnostics",
    "quintiles",
    "ralphlauren",
    "raymondjames",
    "raytheon",
    "realogy",
    "redirect",
    "regions",
    "register",
    "relay",
    "remote",
    "report",
    "reports",
    "republicservices",
    "research",
    "reviews",
    "reynoldsamerican",
    "rgare",
    "riteaid",
    "rockwellautomation",
    "rockwellcollins",
    "root",
    "rossstores",
    "router",
    "rrdonnelley",
    "rsac",
    "rss",
    "rt",
    "ru",
    "ryder",
    "s",
    "sales",
    "salesforce",
    "sandbox",
    "sandisk",
    "sands",
    "sanmina",
    "seaboardcorp",
    "sealedair",
    "search",
    "searsholdings",
    "secure",
    "sempra",
    "seo",
    "server",
    "service",
    "services",
    "setting",
    "settings",
    "sftp",
    "share",
    "sharepoint",
    "sherwin",
    "shop",
    "shopping",
    "show",
    "simon",
    "sip",
    "site",
    "sitebuilder",
    "sitemap",
    "sites",
    "sjm",
    "sms",
    "smtp",
    "social",
    "software",
    "sonicautomotive",
    "southerncompany",
    "southwest",
    "sp",
    "spam",
    "spartannash",
    "spectraenergy",
    "speedtest",
    "spglobal",
    "spiritaero",
    "sport",
    "sports",
    "sql",
    "ssh",
    "ssl",
    "sso",
    "st",
    "staff",
    "stage",
    "staging",
    "stanleyblackanddecker",
    "staples",
    "starbucks",
    "start",
    "starwoodhotels",
    "stat",
    "statefarm",
    "statestreet",
    "static",
    "statistics",
    "stats",
    "status",
    "steeldynamics",
    "storage",
    "store",
    "stream",
    "streaming",
    "stryker",
    "student",
    "style",
    "styles",
    "suntrust",
    "supervalu",
    "support",
    "survey",
    "sv",
    "svn",
    "symantec",
    "syn",
    "syndicated",
    "synnex",
    "sysco",
    "system",
    "t",
    "ta-petrol",
    "tag",
    "tags",
    "targaresources",
    "target",
    "tdsinc",
    "team",
    "teams",
    "tech",
    "techdata",
    "temp",
    "tenethealth",
    "tenneco",
    "terex",
    "termsofservice",
    "test",
    "testing",
    "textron",
    "thecloroxcompany",
    "thehartford",
    "thehersheycompany",
    "thekrogerco",
    "thermofisher",
    "thrivent",
    "thumbs",
    "ti",
    "tiaa",
    "ticket",
    "tickets",
    "time",
    "timewarner",
    "tjx",
    "tmp",
    "tool",
    "tools",
    "tos",
    "toysrusinc",
    "trac",
    "track",
    "tracker",
    "tracking",
    "tractorsupply",
    "training",
    "travel",
    "travelers",
    "trin",
    "ts",
    "tsocorp",
    "tv",
    "tw",
    "twc",
    "tysonfoods",
    "ugicorp",
    "uhsinc",
    "uk",
    "unfi",
    "unitedcontinentalholdings",
    "unitedhealthgroup",
    "unitedrentals",
    "univar",
    "unum",
    "up",
    "update",
    "updates",
    "upgrade",
    "upgrades",
    "upi",
    "upload",
    "ups",
    "us",
    "usaa",
    "usbank",
    "user",
    "username",
    "usernames",
    "users",
    "usfoods",
    "ussteel",
    "utc",
    "v",
    "valero",
    "vc",
    "veritivcorp",
    "verizon",
    "vfc",
    "viacom",
    "video",
    "videos",
    "vip",
    "visa",
    "visteon",
    "vod",
    "voip",
    "volunteer",
    "volunteers",
    "voya",
    "vpn",
    "vps",
    "w",
    "w3",
    "walgreensbootsalliance",
    "walmart",
    "wap",
    "web",
    "webconf",
    "webdisk",
    "webmail",
    "webmaster",
    "wecenergygroup",
    "wellcare",
    "wellsfargo",
    "wesco",
    "westerndigital",
    "westernsouthern",
    "westernunion",
    "westrock",
    "weyerhaeuser",
    "wfscorp",
    "whirlpoolcorp",
    "whm",
    "wholefoodsmarket",
    "wifi",
    "wiki",
    "williams",
    "windstream",
    "wm",
    "wnr",
    "wordpress",
    "work",
    "wp",
    "wrberkley",
    "ws",
    "ww",
    "ww1",
    "ww2",
    "ww3",
    "www",
    "www2",
    "wyndhamworldwide",
    "xcelenergy",
    "xerox",
    "xml",
    "xmpp",
    "xpo",
    "yaml",
    "yum",
    "zimmerbiomet",
}

RESERVED_ROOT_LABELS: set[str] = {
    "abuse",
    "account",
    "admin",
    "api",
    "app",
    "assets",
    "auth",
    "autoconfig",
    "autodiscover",
    "alpha",
    "beta",
    "billing",
    "blog",
    "bounce",
    "noreply",
    "cache",
    "content",
    "canary",
    "cdn",
    "checkout",
    "cpanel",
    "dashboard",
    "dev",
    "development",
    "dns",
    "docs",
    "ftp",
    "fsbot",
    "help",
    "health",
    "healthcheck",
    "hostmaster",
    "koti",
    "home",
    "kofi",
    "login",
    "imap",
    "localhost",
    "signin",
    "mail",
    "monitor",
    "monitoring",
    "mta-sts",
    "mx",
    "origin",
    "panel",
    "pop",
    "pop3",
    "postmaster",
    "redeem",
    "register",
    "root",
    "sentry",
    "smtp",
    "staging",
    "static",
    "status",
    "support",
    "test",
    "testing",
    "webmail",
    "www",
    "ns",
    "wpad",
    "isatap",
    "whois",
    "resolver",
    "nameserver",
    "security",
    "terms",
    "dmarc",
    "spf",
    "dkim",
    "bimi",
    "tls-rpt",
    "well-known",
    "serveo",
    "tunnel",
    "tunnels",
    "socks",
    "sshd",
}

RESERVED = {*RESERVED_ROOT_LABELS, *GITHUB_LIST}

REGEX_PATTERNS: list[re.Pattern[str]] = [
    re.compile(ptn)
    for ptn in [
        r"ns[0-9]+",
        r"_.*",
        r"xn--.*",
        r"www[0-9]*",
        r"^ww[0-9]*$",
    ]
]


class Validation:
    def __init__(self, table: Domains, dns: "DNS") -> None:
        self.dns = dns
        self.table = table

    @staticmethod
    def is_reserved_label(label: str) -> bool:
        if label in RESERVED:
            return True

        return any(pattern.fullmatch(label) is not None for pattern in REGEX_PATTERNS)

    @staticmethod
    def record_name_valid(name: str, type: str) -> bool:
        if not name or len(name.removesuffix(".")) > 253:
            return False

        always_allowed: list[str] = list(string.ascii_letters + string.digits)

        if type.upper() in {"TXT", "CNAME"}:
            always_allowed.append("_")

        allowed_end = always_allowed.copy()
        allowed = always_allowed.copy()
        allowed.extend([".", "-"])

        if type.upper() == "CNAME":
            allowed_end.append(".")

        for part in name.removesuffix(".").split("."):
            if len(part) == 0 or len(part) > 63:
                return False
            if part.startswith("-") or part.endswith("-"):
                return False

        valid: bool = all(char in allowed for char in name)

        if type.upper() != "TXT" and (name[0] not in always_allowed or name[-1] not in allowed_end):
            valid = False
        return valid

    @staticmethod
    def record_value_valid(values: list[str], type: str) -> bool:
        if type.upper() == "TXT":
            return True

        all_valid: bool = True

        if len(set(values)) != len(values):
            logger.info("Found duplicate values in check, not valid")
            all_valid = False

        for value in values:
            if type.upper() == "CNAME":
                if len(values) != 1:
                    logger.info("CNAME record can only have a single value")
                    all_valid = False
                if not Validation.record_name_valid(value, type):
                    all_valid = False

            elif type.upper() == "A":
                allowed: list[str] = list(string.digits)
                allowed.append(".")

                basic = all(char in allowed for char in value) and value.count(".") == 3
                if not basic:
                    all_valid = False

                for part in value.split("."):
                    if len(part) > 3:
                        all_valid = False

                    try:
                        octet = int(part)
                        if octet > 255:
                            logger.info("Octet is too big, not valid")
                            all_valid = False
                    except ValueError:
                        logger.info(f"Not a valid octet '{part}'")
                        all_valid = False

            elif type.upper() == "AAAA":
                ipv6_pattern = re.compile(
                    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",
                )
                return re.match(string=value, pattern=ipv6_pattern) is not None
            else:  # If type is not in checks
                logger.error(f"Type {type} is not valid!")
                all_valid = False

        return all_valid

    @staticmethod
    def is_reserved_domain(name: str) -> bool:
        canonical_name = Domains.canonical_domain_name(name)
        subdomain = Domains.separate_domain_into_parts(canonical_name)[0]

        if not subdomain:
            return True

        labels = [label for label in subdomain.split(".") if label]
        return len(labels) == 1 and Validation.is_reserved_label(labels[0])

    @staticmethod
    def find_required_domain(full_domain: str) -> str | None:
        """Finds the highest level of the domain. E.g a.b.eepy.page -> b.eepy.page
        Can be used to detect if domain is a subdomain using `is_subdomain = find_required_domain(...) != None`

        :param full_domain: The full domain name, including the TLD
        :type full_domain: str
        :return: If is subdomain the highest level with the TLD at the end, else None
        :rtype: str | None
        """
        domain, tld = Domains.separate_domain_into_parts(full_domain)

        domain = Domains.canonical_domain_name(domain)
        logger.info(f"Checking if {domain} is subdomain")

        domain_parts: list[str] = Domains.canonical_domain_name(domain).split(".")
        logger.info(domain_parts)
        is_subdomain: bool = len(domain_parts) > 1

        required_domain: str = domain_parts[-1] + "." + Domains.canonical_domain_name(tld)

        return required_domain if is_subdomain else None

    @staticmethod
    def domains_overlap(left: str, right: str) -> bool:
        left_domain = Domains.canonical_full_domain_name(left)
        right_domain = Domains.canonical_full_domain_name(right)

        return (
            left_domain == right_domain
            or left_domain.endswith(f".{right_domain}")
            or right_domain.endswith(f".{left_domain}")
        )

    def is_free(  # noqa: PLR0913
        self,
        name: str,
        type: str,
        domains: dict[str, DomainFormat],
        *,
        user_id: str | None = None,
        user_is_admin: bool = False,
        raise_exceptions: bool = True,
    ) -> bool:
        """
        Checks if a given domain name is free for registration.
        Args:
            name (str): The domain to check.
            type (str): The type of DNS record.
            domains (dict[str, DomainFormat]): A dictionary of domains owned by the user.
            raise_exceptions (bool, optional): Whether to raise exceptions on validation errors. Defaults to True.
        Returns:
            bool: True if the domain name is free, False otherwise.
        Raises:
            ValueError: If the record name is invalid and raise_exceptions is True.
            DNSException: If the DNS record type is invalid and raise_exceptions is True.
            SubdomainError: If the user doesn't own the required domain and raise_exceptions is True.
        """

        name = name.removesuffix(".")
        canonical_domain: str = Domains.canonical_domain_name(name)

        if not canonical_domain.endswith(
            tuple(f".{tld}" for tld in get_args(AVAILABLE_TLDS)),
        ):
            if raise_exceptions:
                msg = f"Invalid record name '{name}' (does not include TLD)"
                raise ValueError(msg)
            return False

        if not Validation.record_name_valid(name, type):
            logger.info(f"{name} Name is not valid")
            if raise_exceptions:
                msg = f"Invalid record name '{name}'"
                raise ValueError(msg)
            return False

        if Validation.is_reserved_domain(name) and not user_is_admin:
            logger.info(f"{name} is reserved")
            if raise_exceptions:
                msg = f"Domain '{name}' is reserved"
                raise ReservedDomainError(msg)
            return False

        if type.upper() not in ALLOWED_TYPES:
            logger.info(f"{type} is not a valid type")

            if raise_exceptions:
                msg = f"Invalid type '{type}'"
                raise DNSException(msg, type_=type)
            return False

        if Domains.get_domain(domains, canonical_domain, type) is not None:
            logger.info(f"User already owns record {canonical_domain} {type}")
            return False

        existing_records = [
            record
            for record in Domains.normalize_domains(domains)
            if record["name"] == Domains.canonical_full_domain_name(canonical_domain)
        ]
        if type.upper() == "CNAME" or any(record["type"] == "CNAME" for record in existing_records):  # noqa: SIM102
            if existing_records:
                logger.info(f"Record type {type} conflicts at {canonical_domain}")
                if raise_exceptions:
                    msg_0 = "Domain record conflicts with an existing CNAME"
                    raise DomainExistsError(msg_0)
                return False

        required_domain: str | None = Validation.find_required_domain(name)

        if required_domain and not Domains.has_domain(domains, required_domain):
            logger.warning(f"User does not own {required_domain}")
            if raise_exceptions:
                msg = f"User doesn't own '{required_domain}'"
                raise SubdomainError(
                    msg,
                    required_domain,
                )
            return False

        for user in self.table.get_table():
            if user_id is not None and user.get("_id") == user_id:
                continue

            for existing_domain in Domains.normalize_domains(user.get("domains", [])):
                if Validation.domains_overlap(canonical_domain, existing_domain["name"]):
                    logger.warning(f"Domain {canonical_domain} overlaps with {existing_domain['name']}")
                    if raise_exceptions:
                        msg = "Domain is already registered"
                        raise DomainExistsError(msg)
                    return False

        logger.info("Domain not found in database.")

        return True

    def user_owns_domain(
        self,
        user_id: str,
        domain: str,
        type: str | None = None,
        user: UserType | None = None,
    ) -> bool:
        """Returns whether user has a specfic domain owned. Can bee passed a user_id or user. If user_id is passed, a database lookup occurs.

        :param user_id: the ID of the user to check
        :type user_id: str
        :param domain: the full domain name
        :type domain: str
        :param user: the user object, if provided, no database lookup occusr, defaults to None
        :type user: UserType | None, optional
        :raises UserNotExistError: if the user does not exist
        :return: whether user owns domain
        :rtype: bool
        """  # noqa: E501
        if not user:
            user_data: UserType | None = self.table.find_user({"_id": user_id})
        else:
            user_data = user
        if user_data is None:
            msg = "User does not exist!"
            raise UserNotExistError(msg)

        return Domains.get_domain(user_data["domains"], domain, type) is not None

    @staticmethod
    def can_user_register(domain: str, user: UserType) -> UserCanRegisterResult:
        """Checks whether users domain limit allows them to register a domain

        :param domain: a beautified domain, eg a.b.eepy.page
        :type domain: str
        :param user: the user who is registering
        :type user: UserType
        :return: whether the user can register
        :rtype: UserCanRegisterResult
        """
        subdomain_amount: int = 0
        is_subdomain = Validation.find_required_domain(domain) is not None

        user_domain_amount = 0
        subdomain_amount = 0

        for user_domain in Domains.domain_names(user["domains"]):
            if Validation.find_required_domain(user_domain):
                subdomain_amount += 1
            else:
                user_domain_amount += 1

        logger.info(
            f"User has {subdomain_amount} subdomains and {user_domain_amount} domains",
        )

        limits = get_account_limits(user)  # pyright: ignore[reportArgumentType]
        user_max_domains = int(limits["max-domains"])
        user_max_subdomains = int(limits["max-subdomains"])

        if not is_subdomain and user_domain_amount >= user_max_domains:
            return UserCanRegisterResult(success=False, comment="Domain limit exceeded")

        if is_subdomain and subdomain_amount >= user_max_subdomains:
            return UserCanRegisterResult(success=False, comment="Subdomain limit exceeded")

        return UserCanRegisterResult(success=True, comment="")
