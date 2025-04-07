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

# The earliest date for which EPSS scores are available
EARLIEST_AVAILABLE_DATE = V1_RELEASE_DATE

# Model version options
MODEL_VERSION_V1 = 'v1'
MODEL_VERSION_V2 = 'v2'
MODEL_VERSION_V3 = 'v3'
MODEL_VERSION_V4 = 'v4'
MODEL_VERSION_ALL = 'all'

# Available model versions
MODEL_VERSIONS = [MODEL_VERSION_V1, MODEL_VERSION_V2, MODEL_VERSION_V3, MODEL_VERSION_V4]

# Default is to include all available versions including v4
DEFAULT_MODEL_VERSIONS = f"{MODEL_VERSION_V1},{MODEL_VERSION_V2},{MODEL_VERSION_V3},{MODEL_VERSION_V4}"

# Version to date mapping
VERSION_TO_DATE = {
    MODEL_VERSION_V1: (V1_RELEASE_DATE, datetime.datetime.strptime(V2_RELEASE_DATE, "%Y-%m-%d").date() - datetime.timedelta(days=1)),
    MODEL_VERSION_V2: (V2_RELEASE_DATE, datetime.datetime.strptime(V3_RELEASE_DATE, "%Y-%m-%d").date() - datetime.timedelta(days=1)),
    MODEL_VERSION_V3: (V3_RELEASE_DATE, datetime.datetime.strptime(V4_RELEASE_DATE, "%Y-%m-%d").date() - datetime.timedelta(days=1)),
    MODEL_VERSION_V4: (V4_RELEASE_DATE, None)  # End date is None (current)
}

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

# Download speed modes
DOWNLOAD_SPEED_POLITE = 'polite'
DOWNLOAD_SPEED_NORMAL = 'normal'
DOWNLOAD_SPEED_FAST = 'fast'
DOWNLOAD_SPEEDS = [DOWNLOAD_SPEED_POLITE, DOWNLOAD_SPEED_NORMAL, DOWNLOAD_SPEED_FAST]
DEFAULT_DOWNLOAD_SPEED = DOWNLOAD_SPEED_NORMAL

# Download configuration
DOWNLOAD_BATCH_DELAY = 0.5     # Seconds to wait between download batches
LARGE_DOWNLOAD_THRESHOLD = 91  # Number of files that trigger a large download warning
DOWNLOAD_WARNING_ENABLED = True # Whether to show warning for large downloads

# Download speed configurations
DOWNLOAD_SPEED_CONFIG = {
    DOWNLOAD_SPEED_POLITE: {
        'max_concurrent': 1,
        'batch_delay': 1.0
    },
    DOWNLOAD_SPEED_NORMAL: {
        'max_concurrent': 5,
        'batch_delay': 0.5
    },
    DOWNLOAD_SPEED_FAST: {
        'max_concurrent': 10,
        'batch_delay': 0.0
    }
}

# For backward compatibility
MAX_CONCURRENT_DOWNLOADS = DOWNLOAD_SPEED_CONFIG[DEFAULT_DOWNLOAD_SPEED]['max_concurrent']

# Retry configuration
DOWNLOAD_RETRY_COUNT = 3      # Number of times to retry failed downloads
DOWNLOAD_RETRY_DELAY = 5      # Seconds to wait between retries (will increase exponentially)
DOWNLOAD_TIMEOUT = 30         # Seconds before timing out a download request

# File handling
OVERWRITE = False

# Score keys
EPSS = 'epss'
PERCENTILE = 'percentile'
CVE = 'cve'
DATE = 'date'
EPSS_VERSION = 'epss_version'  # New constant for version column

# Partitioning keys
PARTITIONING_KEYS = {CVE, DATE}
DEFAULT_PARTITIONING_KEY = DATE

# Sorting keys
DATE_AND_CVE = (DATE, CVE)
DATE_AND_EPSS = (DATE, EPSS)
DEFAULT_SORTING_KEY = DATE_AND_CVE

# How many points to use for floating point precision
FLOATING_POINT_PRECISION = 5
