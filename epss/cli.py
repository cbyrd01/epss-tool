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
@click.option('--download-format', default=DEFAULT_FILE_FORMAT, type=click.Choice(FILE_FORMATS), show_default=True, 
              help='Format for downloading EPSS data files')
@click.option('--include-versions', default=DEFAULT_MODEL_VERSIONS, show_default=True, 
              help='Model versions to include (comma-separated: v1,v2,v3,v4 or "all")')
@click.option('--verify-tls/--no-verify-tls', default=True, help='Verify TLS certificates when downloading scores')
@click.option('--download-speed', type=click.Choice(DOWNLOAD_SPEEDS), default=DEFAULT_DOWNLOAD_SPEED, 
              show_default=True, help='Download speed (polite=1 concurrent/1s delay, normal=5 concurrent/0.5s delay, fast=10 concurrent/no delay)')
@click.option('--data-source', type=click.Choice(DATA_SOURCES), default=DEFAULT_DATA_SOURCE, show_default=True,
              help='Data source (file=CSV files, api=FIRST.org API, file+api=try file then API if file fails)')
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose logging')
@click.pass_context
def main(
    ctx: click.Context, 
    download_format: str,
    include_versions: str,
    verify_tls: bool,
    download_speed: str,
    data_source: str,
    verbose: bool):
    """
    Exploit Prediction Scoring System (EPSS)
    
    By default, all available model versions (v1, v2, v3, v4) are included for comprehensive historical data.
    You can include specific versions using the --include-versions option (e.g. --include-versions v4 or --include-versions v3,v4).
    
    Data can be retrieved from CSV files (default) or the FIRST.org API. The API is rate-limited, so be considerate
    with the --download-speed option when using the API.
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
            file_format=download_format,
            include_v1_scores=include_v1,
            include_v2_scores=include_v2,
            include_v3_scores=include_v3,
            include_v4_scores=include_v4,
            verify_tls=verify_tls,
            download_speed=download_speed,
            data_source=data_source,
        ),
    }


@main.command('scores')
@click.option('--workdir', '-w', default=SCORES_BY_DATE_WORKDIR, show_default=True, help='Work directory')
@click.option('--min-date', '-a', show_default=True, help='Minimum date (YYYY-MM-DD)')
@click.option('--max-date', '-b', help='Maximum date (YYYY-MM-DD)')
@click.option('--output-file', '-o', help='Output file')
@click.option('--output-format', '-f', type=click.Choice(OUTPUT_FORMATS), help='Format for the command output')
@click.option('--output-sort', '-s', help='Sort output (e.g., "-epss,+date" where - is descending, + is ascending)')
@click.option('--drop-unchanged/--no-drop-unchanged', 'drop_unchanged_scores', default=True, show_default=True, help='Drop unchanged scores')
@click.option('--download', is_flag=True, help="Don't write to an output file or the console, just download the data")
@click.option('--no-warnings', is_flag=True, help="Skip all warnings (for large downloads and current day data)")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def get_scores_cli(
    ctx: click.Context, 
    workdir: str,
    min_date: Optional[str],
    max_date: Optional[str],
    output_file: Optional[str],
    output_format: Optional[str],
    output_sort: Optional[str],
    drop_unchanged_scores: bool,
    download: bool,
    no_warnings: bool,
    verbose: bool):
    """
    Get EPSS scores for CVEs
    
    Specify a date range with --min-date and --max-date (both in YYYY-MM-DD format).
    For a single date, set both --min-date and --max-date to the same date.
    
    Sort with --output-sort option using format: "-column1,+column2" where:
    - "-" prefix sorts in descending order
    - "+" prefix sorts in ascending order
    - No prefix defaults to ascending order
    - Multiple columns are separated by commas
    
    Example: --output-sort "-epss,+date" sorts by epss (highest first) then by date (oldest first)
    """
    # Override logging level if verbose flag is specified at subcommand level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    client: Client = ctx.obj['client']
    if download:
        client.download_scores(
            workdir=workdir,
            min_date=min_date,
            max_date=max_date,
            no_warnings=no_warnings,
        )
        
        # Display warning if we had missing dates after download
        if client.missing_dates:
            if len(client.missing_dates) == 1:
                logger.warning("Data for 1 date could not be downloaded: %s", client.missing_dates[0].isoformat())
            else:
                missing_dates_str = ', '.join(d.isoformat() for d in sorted(client.missing_dates)[:10])
                if len(client.missing_dates) > 10:
                    missing_dates_str += f" and {len(client.missing_dates) - 10} more"
                logger.warning("Data for %d dates could not be downloaded: %s", len(client.missing_dates), missing_dates_str)
    else:
        df = client.get_scores(
            workdir=workdir,
            min_date=min_date,
            max_date=max_date,
            drop_unchanged_scores=drop_unchanged_scores,
        )
        
        # Display warning if we had missing dates
        if client.missing_dates:
            if len(client.missing_dates) == 1:
                logger.warning("OUTPUT INCOMPLETE: Data is missing for date: %s", client.missing_dates[0].isoformat())
            else:
                missing_dates_str = ', '.join(d.isoformat() for d in sorted(client.missing_dates)[:10])
                if len(client.missing_dates) > 10:
                    missing_dates_str += f" and {len(client.missing_dates) - 10} more"
                logger.warning("OUTPUT INCOMPLETE: Data is missing for %d dates: %s", len(client.missing_dates), missing_dates_str)
        
        # Apply custom sorting if specified, otherwise use default sorting
        if output_sort:
            df = sort_dataframe_by_spec(df, output_sort)
        else:
            # Default sorting
            df = df.sort(by=['cve'], descending=True)
            df = df.sort(by=['epss'], descending=True)
            df = df.sort(by=['date'], descending=False)
            
        write_output(df, output_file, output_format)
        
        # Display warning after output if we had missing dates
        if client.missing_dates and not output_file:
            logger.warning("NOTE: The output above is incomplete due to missing data for some dates.")


@main.command('urls')
@click.option('--min-date', '-a', show_default=True, help='Minimum date (YYYY-MM-DD)')
@click.option('--max-date', '-b', help='Maximum date (YYYY-MM-DD)')
@click.option('--output-format', '-f', type=click.Choice(OUTPUT_FORMATS), help='Format for the command output')
@click.option('--output-file', '-o', help='Output file')
@click.option('--output-sort', '-s', help='Sort output (e.g., "-urls" where - is descending, + is ascending)')
@click.pass_context
def get_urls_cli(
    ctx: click.Context, 
    min_date: Optional[str],
    max_date: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
    output_sort: Optional[str]):
    """
    Get URLs for EPSS data files
    
    Specify a date range with --min-date and --max-date (both in YYYY-MM-DD format).
    For a single date, set both --min-date and --max-date to the same date.
    
    Sort with --output-sort option using format: "-column" where:
    - "-" prefix sorts in descending order
    - "+" prefix sorts in ascending order
    - No prefix defaults to ascending order
    """
    client: Client = ctx.obj['client']

    urls = client.iter_urls(
        min_date=min_date,
        max_date=max_date,
    )
    df = pl.DataFrame({'urls': urls})
    
    # Apply custom sorting if specified
    if output_sort:
        df = sort_dataframe_by_spec(df, output_sort)
        
    format_to_use = output_format or ctx.parent.params['download_format']
    _output_data(df, format_to_use, output_file)


@main.command('date-range')
@click.option('--min-date', '-a', help='Minimum date (YYYY-MM-DD)')
@click.option('--max-date', '-b', help='Maximum date (YYYY-MM-DD)')
@click.option('--output-format', '-f', type=click.Choice(OUTPUT_FORMATS), help='Format for the command output')
@click.option('--output-file', '-o', help='Output file')
@click.option('--output-sort', '-s', help='Sort output (e.g., "-min_date" where - is descending, + is ascending)')
@click.pass_context
def get_date_range_cli(
    ctx: click.Context, 
    min_date: Optional[str],
    max_date: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
    output_sort: Optional[str]):
    """
    Preview available date ranges for EPSS data
    
    Specify a date range with --min-date and --max-date (both in YYYY-MM-DD format).
    For a single date, set both --min-date and --max-date to the same date.
    
    Sort with --output-sort option using format: "-column" where:
    - "-" prefix sorts in descending order
    - "+" prefix sorts in ascending order
    - No prefix defaults to ascending order
    """
    client: Client = ctx.obj['client']
    min_date, max_date = client.get_date_range(
        min_date=min_date,
        max_date=max_date,
    )
    df = pl.DataFrame([{
        'min_date': min_date.isoformat(),
        'max_date': max_date.isoformat(),
    }])
    
    # Apply custom sorting if specified
    if output_sort:
        df = sort_dataframe_by_spec(df, output_sort)
        
    format_to_use = output_format or ctx.parent.params['download_format']
    _output_data(df, format_to_use, output_file)


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


def _output_data(df, format_to_use, output_file=None):
    """Output data in the specified format to file or console."""
    if output_file:
        if format_to_use == TABLE:
            # Default to CSV for file output when TABLE is selected
            df.write_csv(output_file)
            logger.info(f"Data written to {output_file}")
        else:
            # Use the specified format
            if format_to_use == CSV:
                df.write_csv(output_file)
            elif format_to_use == JSON:
                util.write_json(df, output_file)
            elif format_to_use == JSONL:
                util.write_ndjson(df, output_file)
            elif format_to_use == PARQUET:
                util.write_parquet(df, output_file)
            logger.info(f"Data written to {output_file}")
    else:
        # Print to console
        if format_to_use == TABLE:
            print(df)
        elif format_to_use == CSV:
            print(df.write_csv())
        elif format_to_use == JSON:
            print(json.dumps(df.to_dicts(), cls=JSONEncoder))
        elif format_to_use == JSONL:
            for d in df.to_dicts():
                print(json.dumps(d, cls=JSONEncoder))
        elif format_to_use == PARQUET:
            logger.warning("Cannot display Parquet format to console, showing table instead")
            print(df)


def sort_dataframe_by_spec(df: pl.DataFrame, sort_spec: str) -> pl.DataFrame:
    """Sort dataframe according to a sort specification string.
    
    Format: "-col1,+col2,col3" where:
    - "-" prefix means descending order
    - "+" prefix means ascending order
    - No prefix defaults to ascending order
    - Multiple columns separated by commas
    """
    if not sort_spec:
        return df
        
    parts = [part.strip() for part in sort_spec.split(',')]
    for part in parts:
        if not part:
            continue
            
        descending = False
        col_name = part
        
        if part.startswith('-'):
            descending = True
            col_name = part[1:]
        elif part.startswith('+'):
            col_name = part[1:]
            
        if col_name not in df.columns:
            logger.warning(f"Column '{col_name}' not found in dataframe, skipping sort")
            continue
            
        df = df.sort(by=[col_name], descending=descending)
        
    return df


if __name__ == '__main__':
    main()
