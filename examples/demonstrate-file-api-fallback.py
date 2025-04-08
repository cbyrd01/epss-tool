"""
Example demonstrating how the file+api fallback mechanism works.

This example shows how to use the 'file+api' data source option, which tries
to download scores from CSV files first, then falls back to the FIRST.org API 
if the file download fails.

This is useful for dates where the CSV file might be missing but the data is 
still available through the API.
"""

from epss.client import PolarsClient
from epss.constants import DATA_SOURCE_FILE_API, DOWNLOAD_SPEED_POLITE

import polars as pl
import logging
import tempfile
import os
import datetime

# Configure verbose logging to show the fallback process
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger = logging.getLogger()

cfg = pl.Config()
cfg.set_tbl_rows(10)  # Show only first 10 rows in output

WORKDIR = os.path.join(tempfile.gettempdir(), 'epss-fallback-example')

# Create a client that uses file+api mode
client = PolarsClient(
    data_source=DATA_SOURCE_FILE_API,
    download_speed=DOWNLOAD_SPEED_POLITE,
    include_v1_scores=True,
    include_v2_scores=True,
    include_v3_scores=True,
    include_v4_scores=True,
)

print("Demonstrating the file+api fallback mechanism...")
print()
print("1. Try using file+api for an old date (April 2021) - likely to need API fallback")
print("   due to older CSV files sometimes being unavailable from the CDN")
print()

# Try a date from the beginning of EPSS where file might be missing
old_date = "2021-04-20"
print(f"Fetching EPSS scores for {old_date}")

try:
    df = client.get_scores_by_date(
        workdir=WORKDIR,
        date=old_date
    )
    
    if not df.is_empty():
        print(f"Success! Got {len(df)} scores")
        print("\nSample data:")
        print(df.head(5))
    else:
        print("No data found for this date.")
        
except Exception as e:
    print(f"Error: {str(e)}")

print("\n2. Try a date range that might include both available and unavailable files")
start_date = datetime.date(2021, 4, 18)
end_date = datetime.date(2021, 4, 22)

print(f"Fetching EPSS scores for range {start_date} to {end_date}")
print("This will try to download files first, then API for any failures")

try:
    df = client.get_scores(
        workdir=WORKDIR,
        min_date=start_date,
        max_date=end_date,
        drop_unchanged_scores=False
    )
    
    if not df.is_empty():
        print(f"Success! Got {len(df)} scores from {len(df.select('date').unique())} dates")
        print("\nScores by date:")
        print(df.group_by('date').agg(pl.count().alias('count')))
    else:
        print("No data found for this date range.")
        
except Exception as e:
    print(f"Error: {str(e)}")

print()
print("Note: When the file download fails, you should see log messages indicating")
print("the fallback to API. Look for messages like:")
print("INFO ... File download failed for YYYY-MM-DD, trying API as fallback")
