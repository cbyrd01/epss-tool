"""
Example showing how to use the FIRST.org EPSS API as a data source.

FIRST.org provides an API for accessing EPSS scores: https://www.first.org/epss/api
This example demonstrates how to use this API instead of downloading CSV files.

Usage examples:

1. Use API exclusively:
   
   client = PolarsClient(data_source=DATA_SOURCE_API)
   
2. Try file downloads first, use API as fallback:
   
   client = PolarsClient(data_source=DATA_SOURCE_FILE_API)
   
3. Control API request rate with download speed:
   
   client = PolarsClient(data_source=DATA_SOURCE_API, download_speed=DOWNLOAD_SPEED_POLITE)
"""

from epss.client import PolarsClient
from epss.constants import DATA_SOURCE_API, DATA_SOURCE_FILE_API, DOWNLOAD_SPEED_POLITE

import polars as pl
import logging
import tempfile
import os

# Configure logging and Polars
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
cfg = pl.Config()
cfg.set_tbl_rows(10)  # Show only first 10 rows in output

WORKDIR = os.path.join(tempfile.gettempdir(), 'epss')

# Example using FIRST.org API with a polite download speed
client = PolarsClient(
    data_source=DATA_SOURCE_API,
    download_speed=DOWNLOAD_SPEED_POLITE,
    include_v1_scores=False,
    include_v2_scores=False,
    include_v3_scores=True,
)

print("Downloading EPSS scores from FIRST.org API (this may take a moment)...")
print()

# Get scores for a single day (to limit API usage in this example)
df = client.get_scores(
    workdir=WORKDIR,
    min_date="2024-01-15",
    max_date="2024-01-15"
)

print(f"Retrieved {len(df)} scores from the API")
print()
print("First 10 scores (sorted by EPSS score):")
print(df.sort("epss", descending=True).head(10))

# Example of using API as a fallback
print()
print("Example of using file+api mode (API as fallback):")
fallback_client = PolarsClient(
    data_source=DATA_SOURCE_FILE_API,
    download_speed=DOWNLOAD_SPEED_POLITE,
)
print("""
In file+api mode, the client will:
1. First try to download CSV files from the Cyentia Institute
2. If a file download fails, try the FIRST.org API as a fallback
3. Successfully downloaded data will be cached locally

This is useful when:
- Some historical data is no longer available as CSV files
- You need to ensure maximum data availability
""")
