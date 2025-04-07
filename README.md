# Exploit Prediction Scoring System (EPSS) tooling

This repository contains a lightning-fast [Python 3 module](epss) and a series of [bash scripts](scripts) that are designed to make it easy for anyone to work with the daily outputs of the [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/).

⚠️ This project is under active development ⚠️

## Features

- Idempotently download daily sets of EPSS scores<sub>1</sub> in JSON, JSONL, CSV, or [Apache Parquet](https://parquet.apache.org/)<sub>2</sub> format
- Explore EPSS scores using [Polars](https://pola.rs/), a lightning-fast dataframe library written in Rust
- Automatic tracking of EPSS model version via the `epss_version` column (1, 2, 3, or 4)
- Optionally drop unchanged scores<sub>3</sub>
- Optionally disable TLS certificate validation when downloading scores (i.e. to support environments where TLS MitM is being performed)
- [Easily](examples/get-scores-as-polars-dataframe.py) [switch](examples/get-changed-scores-as-polars-dataframe.py) between different versions<sub>4</sub> of the [EPSS model](https://www.first.org/epss/model)
- Flexible sorting of results by any column with customizable sort direction

<sub>1. By default, EPSS scores will be downloaded from all EPSS model versions (v1 through v4), but you can restrict to specific versions using the `--include-versions` option.</sub>

<sub>2. Apache Parquet is the default file format.</sub>

<sub>3. The [Cyentia Institute](https://www.cyentia.com/research/) [publishes](https://www.first.org/epss/data_stats) sets of EPSS scores partitioned by date on a daily basis in GZIP compressed CSV format.</sub>

<sub>4. EPSS has undergone 4 major revisions: [EPSS v1](https://arxiv.org/abs/1908.04856), EPSS v2 (v2022.01.01), [EPSS v3 (v2023.03.01)](https://arxiv.org/abs/2302.14172), and EPSS v4 (v2024.03.14) where each revision contains significant improvements.</sub>

## Background

The Exploit Prediction Scoring System (EPSS) is a probabilistic [model](https://www.first.org/epss/model) that is designed to predict the likelihood of a given computer security vulnerability being exploited somewhere in the wild within the next 30 days.

The first version of the EPSS model was released in 2021, and it has since undergone three major revisions, with the latest v4 model released on March 17, 2025.

The first version of the EPSS model used logistic regression, but subsequent models have used [gradient-boosted decision trees](https://en.wikipedia.org/wiki/Gradient_boosting) ([XGBoost](https://en.wikipedia.org/wiki/XGBoost)) to make predictions.

For additional information on EPSS and its applications, please consult the following resources:

- [Exploit Prediction Scoring System (EPSS)](https://arxiv.org/abs/1908.04856)
- [Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights](https://arxiv.org/abs/2302.14172)

Additional resources:

- [Daily analysis of EPSS scores](https://www.first.org/epss/data_stats)
- [The Exploit Prediction Scoring System (EPSS) Explained](https://www.splunk.com/en_us/blog/learn/epss-exploit-prediction-scoring-system.html#:~:text=In%20short%2C%20EPSS%20allows%20us,vulnerability%20might%20be%20if%20exploited.)
- [F5 Labs Joins the Exploit Prediction Scoring System as a Data Partner](https://www.f5.com/labs/articles/cisotociso/f5-labs-joins-the-exploit-prediction-scoring-system-as-a-data-partner)

## Installation

### Direct Installation

The simplest way to install the EPSS tool is to clone the repository and use Poetry:

```bash
# Clone the repository
git clone https://github.com/whitfieldsdad/epss-tool.git
cd epss-tool

# Install with Poetry
poetry install
```

This will create a virtual environment and install all dependencies.

### Adding as a Dependency to Another Project

If you want to use the EPSS tool as a dependency in another project, you can add it using Poetry:

```bash
# Add from GitHub
poetry add git+https://github.com/whitfieldsdad/epss.git
```

You can also specify a branch or tag:

```bash
# From a specific branch
poetry add git+https://github.com/whitfieldsdad/epss.git#main

# From a specific tag/version
poetry add git+https://github.com/whitfieldsdad/epss.git#v3.0.0
```

### Alternative Installation with pip

You can also install directly with pip using the requirements.txt file:

```bash
# Clone the repository
git clone https://github.com/whitfieldsdad/epss-tool.git
cd epss-tool

# Install with pip
pip install -r requirements.txt
```

Or add it as a dependency in your own requirements.txt file:

```
git+https://github.com/whitfieldsdad/epss@v3.0.0
```

## Usage

### Command Line Interface

The EPSS tool provides a comprehensive CLI for working with EPSS data. Here are the main commands:

#### 1. Viewing EPSS Scores

The `scores` command retrieves and displays EPSS scores:

```bash
# View scores from a specific date range
poetry run epss scores -a 2024-01-01 -b 2024-01-31

# View only scores that changed (more efficient)
poetry run epss scores -a 2024-01-01 --drop-unchanged
```

**Key options:**
- `-a, --min-date`: Starting date (YYYY-MM-DD)
- `-b, --max-date`: Ending date (YYYY-MM-DD)
- `--drop-unchanged/--no-drop-unchanged`: Whether to exclude scores that haven't changed
- `--output-format`: Format for output (table, csv, json, jsonl, parquet)
- `--output-file`: Save output to a file instead of displaying it
- `--output-sort`: Sort results (e.g., "-epss,+date")
- `--download`: Download scores without displaying them

Example output:

```text
shape: (33_592, 5)
┌──────────────────┬─────────┬────────────┬────────────┬──────────────┐
│ cve              ┆ epss    ┆ percentile ┆ date       ┆ epss_version │
│ ---              ┆ ---     ┆ ---        ┆ ---        ┆ ---          │
│ str              ┆ f64     ┆ f64        ┆ date       ┆ i64          │
╞══════════════════╪═════════╪════════════╪════════════╪══════════════╡
│ CVE-2019-1653    ┆ 0.97555 ┆ 0.99998    ┆ 2024-01-03 ┆ 3            │
│ CVE-2020-14750   ┆ 0.97544 ┆ 0.99995    ┆ 2024-01-03 ┆ 3            │
│ CVE-2013-2423    ┆ 0.97512 ┆ 0.99983    ┆ 2024-01-03 ┆ 3            │
│ CVE-2019-19781   ┆ 0.97485 ┆ 0.99967    ┆ 2024-01-03 ┆ 3            │
```

#### 2. Model Version Selection

Control which EPSS model versions to include:

```bash
# Only use v4 scores (latest model)
poetry run epss --include-versions v4 scores -a 2024-03-17

# Use both v3 and v4 scores
poetry run epss --include-versions v3,v4 scores -a 2023-03-07

# Include all model versions (default behavior)
poetry run epss --include-versions all scores
```

#### 3. Downloading EPSS Data

To download scores without displaying them:

```bash
# Download scores for a date range
poetry run epss scores -a 2024-01-01 -b 2024-01-31 --download
```

#### 4. Output Format Options

Control the output format:

```bash
# Output as CSV
poetry run epss scores -a 2024-01-01 --output-format=csv

# Output as JSONL
poetry run epss scores -a 2024-01-01 --output-format=jsonl

# Save to a file
poetry run epss scores -a 2024-01-01 --output-file=scores.csv
```

#### 5. Sorting Results

Sort your results with the flexible sorting syntax:

```bash
# Sort by EPSS score (highest first)
poetry run epss scores -a 2024-01-01 --output-sort="-epss"

# Sort by date (newest first) then by EPSS score (highest first)
poetry run epss scores -a 2024-01-01 --output-sort="-date,-epss"
```

**Sort format:**
- `-column`: Sort in descending order (highest values first)
- `+column`: Sort in ascending order (lowest values first)
- `column`: Same as `+column` (ascending order)
- Multiple columns: Separate by commas (e.g., `-epss,+date`)

### Python API

The EPSS tool can also be used programmatically in your Python code. Additional examples are available in the [examples](examples) folder.

#### Basic Example: Loading EPSS Scores

```python
from epss.client import PolarsClient

import polars as pl
import tempfile
import os

# Configure Polars to show all rows
cfg = pl.Config()
cfg.set_tbl_rows(-1)

# Set up a temporary work directory
WORKDIR = os.path.join(tempfile.gettempdir(), 'epss')

# Initialize the client - use only the v4 model
client = PolarsClient(
    include_v1_scores=False,
    include_v2_scores=False,
    include_v3_scores=False,
    include_v4_scores=True,  # Only include the latest v4 model
)

# Get scores with changes only
df = client.get_scores(workdir=WORKDIR, drop_unchanged_scores=True)
print(df)
```

#### Example: Generating a Spreadsheet of Changed EPSS Scores

```python
from xlsxwriter import Workbook
from epss.client import PolarsClient, Query

import tempfile
import os

WORKDIR = os.path.join(tempfile.gettempdir(), 'epss')

# Initialize client with v4 model only
client = PolarsClient(
    include_v1_scores=False,
    include_v2_scores=False,
    include_v3_scores=False,
    include_v4_scores=True,
)

# Set up a query for specific CVEs
query = Query(
    cve_ids=[
        'CVE-2019-11510',
        'CVE-2020-1472',
        'CVE-2018-13379',
        # ... more CVE IDs ...
    ]
)

# Get the scores for these CVEs
df = client.get_scores(
    workdir=WORKDIR,
    query=query,
    drop_unchanged_scores=True
)

# Write to Excel
with Workbook('epss.xlsx') as wb:
    df.write_excel(
        workbook=wb,
        worksheet='CVE Tracking'
    )
```