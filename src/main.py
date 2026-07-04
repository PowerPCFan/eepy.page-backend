import os
import sys
import time

from dotenv import load_dotenv

load_dotenv()
os.environ["ZONE_ID"] = os.getenv("ZONEID") or os.getenv("ZONE_ID") or "None"

start = time.time()
from server.main import app  # noqa: E402

os.environ["START_ELAPSED"] = str(round(time.time() - start, 2))
os.environ["STARTED_AT"] = str(start)


if __name__ == "__main__":
    if "run" in sys.argv:
        os.environ["DEBUG"] = "True"

        import uvicorn  # pyright: ignore[reportMissingImports]

        uvicorn.run(app, host="0.0.0.0")  # noqa: S104
    else:
        print(
            "WARNING: If you are trying to self host and want to use uvicorn for debug mode, please run `python src/main.py run`",  # noqa: E501
        )
else:
    print("This script should not be imported as a module.")
