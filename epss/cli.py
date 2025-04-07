from typing import Optional
from epss.constants import *
from epss.client import PolarsClient as Client
from epss.json_encoder import JSONEncoder
from epss import util
import requests.packages
import polars as pl
import logging
import click
import json

logger = logging.getLogger(__name__)

# No limit on output length
cfg = pl.Config()
cfg.set_tbl_rows(-1)

DEFAULT_TABLE_NAME = 'df'

TABLE = 'table'
OUTPUT_FORMATS = FILE_FORMATS + [TABLE]

DEFAULT_FILE_OUTPUT_FORMAT = PARQUET
DEFAULT_CONSOLE_OUTPUT_FORMAT = TABLE


@click.group()
@click.option('--file-format', default=DEFAULT_FILE_FORMAT, type=click.Choice(FILE_FORMATS), show_default=True, help='File format')
@click.option('--include-versions', default=DEFAULT_MODEL_VERSIONS, show_default=True, 
              help='Model versions to include (comma-separated: v1,v2,v3,v4 or "all")')
@click.option('--verify-tls/--no-verify-tls', default=True, help='Verify TLS certificates when downloading scores')
@click.option('--download-speed', type=click.Choice(DOWNLOAD_SPEEDS), default=DEFAULT_DOWNLOAD_SPEED, 
              show_default=True, help='Download speed (polite=1 concurrent/1s delay, normal=5 concurrent/0.5s delay, fast=10 concurrent/no delay)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def main(
    ctx: click.Context, 
    file_format: str,
    include_versions: str,
    verify_tls: bool,
    download_speed: str,
    verbose: bool):
    """
    Exploit Prediction Scoring System (EPSS)
    
    By default, all available model versions (v1, v2, v3) are included for comprehensive historical data.
    You can include specific versions using the --include-versions option (e.g. --include-versions v3 or --include-versions v1,v2).
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s %(name)s %(message)s')

    if verify_tls is False:
        requests.packages.urllib3.disable_warnings() 

    # Process the include_versions option
    versions = include_versions.lower().strip()
    include_v1 = False
    include_v2 = False
    include_v3 = False
    include_v4 = False
    
    if versions == MODEL_VERSION_ALL:
        include_v1 = include_v2 = include_v3 = include_v4 = True
    else:
        versions = [v.strip() for v in versions.split(',')]
        include_v1 = MODEL_VERSION_V1 in versions
        include_v2 = MODEL_VERSION_V2 in versions
        include_v3 = MODEL_VERSION_V3 in versions
        include_v4 = MODEL_VERSION_V4 in versions
    
    # Log the selected versions
    selected_versions = []
    if include_v1: selected_versions.append(MODEL_VERSION_V1)
    if include_v2: selected_versions.append(MODEL_VERSION_V2)
    if include_v3: selected_versions.append(MODEL_VERSION_V3)
    if include_v4: selected_versions.append(MODEL_VERSION_V4)
    
    if not selected_versions:
        logger.warning("No model versions selected, defaulting to v3")
        include_v3 = True
        selected_versions.append(MODEL_VERSION_V3)
        
    logger.debug(f"Selected model versions: {', '.join(selected_versions)}")
    
    # Show release date ranges for selected versions
    for version in selected_versions:
        start_date, end_date = VERSION_TO_DATE[version]
        end_str = end_date if end_date else "present"
        logger.debug(f"{version} scores: {start_date} to {end_str}")

    ctx.obj = {
        'client': Client(
            file_format=file_format,
            include_v1_scores=include_v1,
            include_v2_scores=include_v2,
            include_v3_scores=include_v3,
            include_v4_scores=include_v4,
            verify_tls=verify_tls,
            download_speed=download_speed,
        ),
    }


@main.command('scores')
@click.option('--workdir', '-w', default=SCORES_BY_DATE_WORKDIR, show_default=True, help='Work directory')
@click.option('--min-date', '-a', show_default=True, help='Minimum date')
@click.option('--date', '-d', help='Date')
@click.option('--max-date', '-b', help='Maximum date')
@click.option('--output-file', '-o', help='Output file')
@click.option('--output-format', '-f', type=click.Choice(OUTPUT_FORMATS), help='Output format')
@click.option('--drop-unchanged/--no-drop-unchanged', 'drop_unchanged_scores', default=True, show_default=True, help='Drop unchanged scores')
@click.option('--download', is_flag=True, help="Don't write to an output file or the console, just download the data")
@click.option('--no-warning', is_flag=True, help="Skip warning for large downloads")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def get_scores_cli(
    ctx: click.Context, 
    workdir: str,
    min_date: Optional[str],
    date: Optional[str],
    max_date: Optional[str],
    output_file: Optional[str],
    output_format: Optional[str],
    drop_unchanged_scores: bool,
    download: bool,
    no_warning: bool,
    verbose: bool):
    """
    Get scores
    """
    # Override logging level if verbose flag is specified at subcommand level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    if date:
        min_date = date
        max_date = date

    client: Client = ctx.obj['client']
    if download:
        client.download_scores(
            workdir=workdir,
            min_date=min_date,
            max_date=max_date,
            no_warning=no_warning,
        )
    else:
        df = client.get_scores(
            workdir=workdir,
            min_date=min_date,
            max_date=max_date,
            drop_unchanged_scores=drop_unchanged_scores,
        )
        df = df.sort(by=['cve'], descending=True)
        df = df.sort(by=['epss'], descending=True)
        df = df.sort(by=['date'], descending=False)
        write_output(df, output_file, output_format)


@main.command('urls')
@click.option('--min-date', '-a', show_default=True, help='Minimum date')
@click.option('--max-date', '-b', help='Maximum date')
@click.option('--date', '-d', help='Date')
@click.pass_context
def get_urls_cli(
    ctx: click.Context, 
    min_date: Optional[str],
    max_date: Optional[str],
    date: Optional[str]):
    """
    Get URLs
    """
    client: Client = ctx.obj['client']

    if date:
        min_date = date
        max_date = date

    urls = client.iter_urls(
        min_date=min_date,
        max_date=max_date,
    )
    for url in urls:
        print(url)


@main.command('date-range')
@click.option('--min-date', '-a', help='Minimum date')
@click.option('--max-date', '-b', help='Maximum date')
@click.pass_context
def get_date_range_cli(
    ctx: click.Context, 
    min_date: Optional[str],
    max_date: Optional[str]):
    """
    Preview date ranges
    """
    client: Client = ctx.obj['client']
    min_date, max_date = client.get_date_range(
        min_date=min_date,
        max_date=max_date,
    )
    print(json.dumps({
        'min_date': min_date.isoformat(),
        'max_date': max_date.isoformat(),
    }, cls=JSONEncoder))


def write_output(df: pl.DataFrame, output_file: Optional[str], output_format: Optional[str]):
    if output_file:
        output_format = output_format or DEFAULT_FILE_OUTPUT_FORMAT
        util.write_dataframe(df, output_file)
    else:
        output_format = output_format or DEFAULT_CONSOLE_OUTPUT_FORMAT
        if output_format == TABLE:
            print(df)
        elif output_format == JSON:
            print(json.dumps(df.to_dicts(), cls=JSONEncoder))
        elif output_format == JSONL:
            for d in df.to_dicts():
                print(json.dumps(d, cls=JSONEncoder))
        elif output_format == CSV:
            print(df.write_csv()) 
        else:
            raise ValueError(f"Invalid output format: {output_format}")


if __name__ == '__main__':
    main()
