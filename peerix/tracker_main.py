import logging
import asyncio
import argparse

import uvloop
from hypercorn import Config
from hypercorn.asyncio import serve

from peerix.tracker import create_tracker_app


parser = argparse.ArgumentParser(description="Peerix tracker server.")
parser.add_argument("--verbose", action="store_const", const=logging.DEBUG, default=logging.INFO, dest="loglevel")
parser.add_argument("--port", default=12305, type=int)
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--db-path", default="./peerix-tracker.db")


def run():
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)
    uvloop.install()

    app = create_tracker_app(args.db_path)
    asyncio.run(main(app, args.host, args.port))


async def main(app, host: str, port: int):
    config = Config()
    config.bind = [f"{host}:{port}"]
    await serve(app, config)


if __name__ == "__main__":
    run()
