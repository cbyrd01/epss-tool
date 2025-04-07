import datetime
import os
from typing import Iterable, Union
import tempfile

# Cache directory
WORKDIR = os.path.join(tempfile.gettempdir(), '476c9b0d-79c6-4b7e-a31a-e18cec3d6444', 'epss')
SCORES_BY_DATE_WORKDIR = os.path.join(WORKDIR, 'scores-by-date')

# Release dates
V1_RELEASE_DATE = '2021-04-14'  
V2_RELEASE_DATE = '2022-02-04'  # EPSS v2 (v2022.01.01)
V3_RELEASE_DATE = '2023-03-07'  # EPSS v3 (v2023.03.01)
V4_RELEASE_DATE = '2025-03-17'  # EPSS v4 (v2025.03.14)
MIN_DATE = V3_RELEASE_DATE

# Default download URL base
DEFAULT_DOWNLOAD_URL_BASE = "https://epss.empiricalsecurity.com"

# Type hints
TIME = Union[datetime.date, datetime.datetime, str, int, float]
STRS = Iterable[str]

# File formats
CSV = 'csv'
JSON = 'json'
JSONL = 'jsonl'
PARQUET = 'parquet'

FILE_FORMATS = [CSV, JSON, JSONL, PARQUET]
DEFAULT_FILE_FORMAT = PARQUET

# File handling
OVERWRITE = False

# Score keys
EPSS = 'epss'
PERCENTILE = 'percentile'
CVE = 'cve'
DATE = 'date'

# Partitioning keys
PARTITIONING_KEYS = {CVE, DATE}
DEFAULT_PARTITIONING_KEY = DATE

# Sorting keys
DATE_AND_CVE = (DATE, CVE)
DATE_AND_EPSS = (DATE, EPSS)
DEFAULT_SORTING_KEY = DATE_AND_CVE

# How many points to use for floating point precision
FLOATING_POINT_PRECISION = 5
