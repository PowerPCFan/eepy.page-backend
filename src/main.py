import os
import sys
import time

from dotenv import load_dotenv

load_dotenv()

start = time.time()
os.environ["START_ELAPSED"] = str(round(time.time() - start, 2))
os.environ["STARTED_AT"] = str(start)


if __name__ == "__main__":
    if "run" in sys.argv:
        os.environ["DEBUG"] = "True"
        print("====================\nDebug mode enabled\n====================")
        print("This mode is only intended for running local development instances of this backend.")
        print("Running the backend with `python3 src/main.py run` will automatically enable debug mode.")

        try:
            import uvicorn  # pyright: ignore[reportMissingImports]
        except ImportError:
            print("Uvicorn is not installed. Please install it with `pip install uvicorn` and try again.")
            sys.exit(1)

        print("\n")
        host, port = str(input("Please enter the host and port you'd like to use (e.g. 0.0.0.0:8000) and press enter >>> ")).split(":")  # noqa: E501
        host_c = str(host).strip().lower()
        port_c = int(str(port).strip().lower())

        print(f"Starting uvicorn on {host_c}:{port_c}...\n\n")

        from server.main import app
        uvicorn.run(app, host=host_c, port=port_c)
    else:
        print(
            "WARNING: If you are trying to self host and want to use uvicorn for debug mode, please run `python src/main.py run`",  # noqa: E501
        )
else:
    print("This script should not be imported as a module.")
