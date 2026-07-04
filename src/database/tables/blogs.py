import logging
import time

from pymongo import MongoClient

from database.table import Table

logger: logging.Logger = logging.getLogger("eepy.page")


class Blogs(Table):
    def __init__(self, mongo_client: MongoClient) -> None:
        super().__init__(mongo_client, "blog")

    def create(self, title: str, body: str) -> None:
        url = title.lower().replace(" ", "-")
        self.insert_document(
            {"_id": url[:24], "date": round(time.time()), "title": title, "body": body},
        )
