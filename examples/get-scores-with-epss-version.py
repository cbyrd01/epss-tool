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
)

# Get scores for all versions
df = client.get_scores(
    workdir=WORKDIR,
    drop_unchanged_scores=True,
)

# Display score counts by EPSS version
print("EPSS Score counts by version:")
print(df.group_by("epss_version").agg(pl.count().alias("count")))

# Filter to only show EPSS version 3 scores
df_v3 = df.filter(pl.col("epss_version") == 3)
print("\nEPSS version 3 scores (first 10):")
print(df_v3.head(10))

# Compare scores across different EPSS versions for a specific CVE
cve_example = "CVE-2019-0708"  # BlueKeep
print(f"\nScores for {cve_example} across EPSS versions:")
print(df.filter(pl.col("cve") == cve_example).sort(by="date"))
