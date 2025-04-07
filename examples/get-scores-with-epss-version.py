from epss.client import PolarsClient, Query

import polars as pl
import logging
import tempfile
import os

cfg = pl.Config()
cfg.set_tbl_rows(-1)    # Unlimited output length

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')

WORKDIR = os.path.join(tempfile.gettempdir(), 'epss')

# Initialize a client that includes all model versions
client = PolarsClient(
    include_v1_scores=True,
    include_v2_scores=True,
    include_v3_scores=True,
    include_v4_scores=True,
)

# Get scores for all versions
df = client.get_scores(
    workdir=WORKDIR,
    drop_unchanged_scores=True,
)

# Display score counts by EPSS version
print("EPSS Score counts by version:")
print(df.group_by("epss_version").agg(pl.count().alias("count")))

# Filter to only show EPSS version 4 scores (newest version)
df_v4 = df.filter(pl.col("epss_version") == 4)
print("\nEPSS version 4 scores (first 10):")
print(df_v4.head(10))

# Compare scores across different EPSS versions for a specific CVE
cve_example = "CVE-2019-0708"  # BlueKeep
print(f"\nScores for {cve_example} across EPSS versions:")
print(df.filter(pl.col("cve") == cve_example).sort(by="date"))

# Add note about EPSS version date ranges
print("\nEPSS version date ranges:")
print(" - Version 1: 2021-04-14 to 2022-02-03")
print(" - Version 2: 2022-02-04 to 2023-03-06")
print(" - Version 3: 2023-03-07 to 2025-03-16")
print(" - Version 4: 2025-03-17 onwards")
