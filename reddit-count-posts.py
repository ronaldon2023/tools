#!/usr/bin/env python3
"""
Reddit global post-rate monitor
- Uses free OAuth (script app)
- Logs posts/minute to CSV + console
- Runs forever (Ctrl-C to stop)
"""

import os
import time
import csv
from datetime import datetime, timezone
from pathlib import Path

import praw
from dotenv import load_dotenv

load_dotenv()   # reads .env

# ----------------------------------------------------------------------
# 1. Reddit OAuth (free tier)
# ----------------------------------------------------------------------
reddit = praw.Reddit(
    client_id=os.getenv("REDDIT_CLIENT_ID"),
    client_secret=os.getenv("REDDIT_CLIENT_SECRET"),
    user_agent=os.getenv("REDDIT_USER_AGENT"),
)

# ----------------------------------------------------------------------
# 2. Helper – get the *current* highest post ID (global)
# ----------------------------------------------------------------------
def get_current_max_post_id() -> int:
    """
    Reddit does not expose a direct "max id" endpoint.
    The trick: request the newest post from the front-page (limit=1)
    and read its fullname (t3_XXXXXX).  The numeric part is the global counter.
    """
    # /r/all/new is the fastest way to surface the newest post
    newest = next(reddit.subreddit("all").new(limit=1))
    # fullname looks like "t3_1c0z2a"
    raw_id = newest.name
    assert raw_id.startswith("t3_")
    # base-36 → decimal
    return int(raw_id[3:], 36)


# ----------------------------------------------------------------------
# 3. CSV logger
# ----------------------------------------------------------------------
LOG_FILE = Path("reddit_rate_log.csv")
if not LOG_FILE.exists():
    LOG_FILE.write_text("timestamp_utc,post_id,posts_since_start,elapsed_min,posts_per_min\n")

def log_measurement(post_id: int, posts_since_start: int, elapsed_min: float):
    now = datetime.now(timezone.utc).isoformat()
    posts_per_min = posts_since_start / elapsed_min if elapsed_min > 0 else 0
    with LOG_FILE.open("a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([now, post_id, posts_since_start, f"{elapsed_min:.3f}", f"{posts_per_min:.1f}"])
    print(f"{now[:19]} | ID t3_{post_id:036} | +{posts_since_start} posts | "
          f"{elapsed_min:.1f} min → **{posts_per_min:.1f} posts/min**")


# ----------------------------------------------------------------------
# 4. Main loop
# ----------------------------------------------------------------------
INTERVAL_SECONDS = 60          # measure every minute (feel free to lower to 30)
SLEEP_BUFFER = 2               # give Reddit a breather

def main():
    print("Reddit rate monitor started – press Ctrl-C to stop")
    start_time = time.time()
    prev_id = get_current_max_post_id()
    posts_since_start = 0

    while True:
        time.sleep(INTERVAL_SECONDS - SLEEP_BUFFER)

        try:
            cur_id = get_current_max_post_id()
        except Exception as e:
            print(f"API error: {e} – retrying in next cycle")
            continue

        delta = cur_id - prev_id
        if delta < 0:
            # Very rare wrap-around – just reset
            print("ID wrapped – resetting baseline")
            prev_id = cur_id
            continue

        posts_since_start += delta
        elapsed_min = (time.time() - start_time) / 60.0

        log_measurement(cur_id, delta, elapsed_min)

        prev_id = cur_id


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user. CSV saved to:", LOG_FILE)
