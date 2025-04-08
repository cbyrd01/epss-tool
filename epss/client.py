from dataclasses import dataclass
import datetime
import functools
import io
import itertools
import os
import re
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

import requests
from epss import util
from epss.constants import (
    DEFAULT_FILE_FORMAT, TIME, V1_RELEASE_DATE, V2_RELEASE_DATE, 
    V3_RELEASE_DATE, V4_RELEASE_DATE, DEFAULT_DOWNLOAD_URL_BASE,
    MAX_CONCURRENT_DOWNLOADS, DOWNLOAD_RETRY_COUNT, DOWNLOAD_RETRY_DELAY,
    DOWNLOAD_TIMEOUT, LARGE_DOWNLOAD_THRESHOLD, DOWNLOAD_WARNING_ENABLED,
    CURRENT_DAY_WARNING_ENABLED, DOWNLOAD_SPEED_CONFIG, DEFAULT_DOWNLOAD_SPEED, 
    DOWNLOAD_SPEEDS, MODEL_VERSION_V1, MODEL_VERSION_V2, MODEL_VERSION_V3, 
    MODEL_VERSION_V4, DEFAULT_MODEL_VERSIONS, VERSION_TO_DATE, EPSS_VERSION,
    DATA_SOURCE_FILE, DATA_SOURCE_API, DATA_SOURCE_FILE_API, DATA_SOURCES,
    DEFAULT_DATA_SOURCE, API_BASE_URL, API_DEFAULT_LIMIT, API_RATE_LIMITS
)
import polars as pl
import concurrent.futures

import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Query:
    cve_ids: Optional[Iterable[str]] = None
    min_epss: Optional[float] = None
    max_epss: Optional[float] = None
    min_percentile: Optional[float] = None
    max_percentile: Optional[float] = None


@dataclass()
class ClientInterface:
    def get_scores(
            self, 
            workdir: str,
            min_date: Optional[TIME] = None, 
            max_date: Optional[TIME] = None,
            query: Optional[Query] = None,
            drop_unchanged_scores: bool = True) -> Any:
        """
        Returns a dataframe containing EPSS scores published between the specified dates.
        
        The dataframe will be sorted by date and CVE ID in descending order.
        """
        raise NotImplementedError()
    
    def get_scores_by_date(
            self,
            workdir: str, 
            date: Optional[TIME] = None,
            query: Optional[Query] = None) -> Any:
        """
        Returns a dataframe containing EPSS scores published on the specified date.

        The dataframe will be sorted by CVE ID in descending order.
        """
        raise NotImplementedError()
    
    def download_scores(
            self,
            workdir: str,
            min_date: Optional[TIME] = None,
            max_date: Optional[TIME] = None,
            no_warnings: bool = False):
        """
        Download EPSS scores published between the specified dates.
        
        Args:
            workdir: Directory to download scores to
            min_date: Minimum date to download scores for (inclusive)
            max_date: Maximum date to download scores for (inclusive)
            no_warnings: If True, skip all warnings (large downloads and current day)
        """
        raise NotImplementedError()


@dataclass()
class BaseClient(ClientInterface):
    file_format: str = DEFAULT_FILE_FORMAT
    verify_tls: bool = True
    include_v1_scores: bool = MODEL_VERSION_V1 in DEFAULT_MODEL_VERSIONS.split(',')
    include_v2_scores: bool = MODEL_VERSION_V2 in DEFAULT_MODEL_VERSIONS.split(',')
    include_v3_scores: bool = MODEL_VERSION_V3 in DEFAULT_MODEL_VERSIONS.split(',')
    include_v4_scores: bool = MODEL_VERSION_V4 in DEFAULT_MODEL_VERSIONS.split(',')
    download_url_base: str = DEFAULT_DOWNLOAD_URL_BASE
    download_speed: str = DEFAULT_DOWNLOAD_SPEED
    data_source: str = DEFAULT_DATA_SOURCE
    missing_dates: List[datetime.date] = None  # Track missing dates
    
    def __post_init__(self):
        if self.missing_dates is None:
            self.missing_dates = []
        
        if self.data_source not in DATA_SOURCES:
            raise ValueError(f"Invalid data source: {self.data_source}. Must be one of {DATA_SOURCES}")
    
    @property
    def max_concurrent_downloads(self) -> int:
        """Returns the maximum number of concurrent downloads based on download speed."""
        return DOWNLOAD_SPEED_CONFIG[self.download_speed]['max_concurrent']
    
    @property
    def batch_delay(self) -> float:
        """Returns the delay between download batches based on download speed."""
        return DOWNLOAD_SPEED_CONFIG[self.download_speed]['batch_delay']

    @property
    def min_date(self) -> datetime.date:
        return self.get_min_date()
    
    @property
    def max_date(self) -> datetime.date:
        return self.get_max_date()
    
    @property
    def date_range(self) -> Tuple[datetime.date, datetime.date]:
        return self.get_date_range()

    def get_min_date(self) -> datetime.date:
        """
        Returns the earliest publication date for EPSS scores under the specified model version constraints.
        """
        return get_min_date(
            include_v1_scores=self.include_v1_scores,
            include_v2_scores=self.include_v2_scores,
            include_v3_scores=self.include_v3_scores,
            include_v4_scores=self.include_v4_scores,
        )

    def get_max_date(self) -> datetime.date:
        """
        Returns the latest publication date for EPSS scores under the specified model version constraints.
        """
        return get_max_date(
            include_v1_scores=self.include_v1_scores,
            include_v2_scores=self.include_v2_scores,
            include_v3_scores=self.include_v3_scores,
            include_v4_scores=self.include_v4_scores,
            verify_tls=self.verify_tls,
            download_url_base=self.download_url_base,
        )
    
    def get_date_range(self, min_date: Optional[TIME] = None, max_date: Optional[TIME] = None) -> Tuple[datetime.date, datetime.date]:
        """
        Returns a tuple containing the earliest and latest publication dates for EPSS scores under the specified model version constraints.
        
        The date range is constrained by:
        1. The model versions selected (include_v1_scores, include_v2_scores, etc.)
        2. The explicit min_date and max_date parameters
        
        For example:
        - If include_v1_scores=True and no other versions, dates will be constrained to V1_RELEASE_DATE to V2_RELEASE_DATE-1
        - If include_v1_scores=True and include_v2_scores=True, dates will be from V1_RELEASE_DATE to V3_RELEASE_DATE-1
        - If all versions are included (default), dates will be from V1_RELEASE_DATE to the present
        """
        min_allowed_date = self.get_min_date()
        max_allowed_date = self.get_max_date()
        logger.debug('Model version constraints: %s - %s', min_allowed_date, max_allowed_date)
        
        requested_min = util.parse_date(min_date) if min_date else min_allowed_date
        requested_max = util.parse_date(max_date) if max_date else max_allowed_date
        logger.debug('Requested date range: %s - %s', requested_min, requested_max)

        # Adjust dates to be within allowed range
        final_min_date = max(requested_min, min_allowed_date)
        final_max_date = min(requested_max, max_allowed_date)
        
        if final_min_date != requested_min:
            logger.info('Min date adjusted from %s to %s (based on model version constraints)', 
                     requested_min, final_min_date)
        
        if final_max_date != requested_max:
            logger.info('Max date adjusted from %s to %s (based on model version constraints)', 
                     requested_max, final_max_date)

        logger.info('Using date range: %s - %s', final_min_date, final_max_date)
        return final_min_date, final_max_date
    
    def iter_dates(self, min_date: Optional[TIME] = None, max_date: Optional[TIME] = None) -> Iterator[datetime.date]:
        """
        Returns an iterator that yields dates in the range [min_date, max_date].
        """
        min_date, max_date = self.get_date_range(min_date=min_date, max_date=max_date)
        yield from util.iter_dates_in_range(min_date, max_date)
    
    def download_scores(
            self,
            workdir: str,
            min_date: Optional[TIME] = None,
            max_date: Optional[TIME] = None,
            no_warnings: bool = False):
        """
        Download EPSS scores published between the specified dates.
        """
        min_date, max_date = self.get_date_range(min_date=min_date, max_date=max_date)
        logger.info('Downloading scores for date range: %s - %s', min_date, max_date)
        
        # Clear missing dates before new download operation
        self.missing_dates = []
        
        # Check if the date range includes the current day
        today = datetime.date.today()
        if CURRENT_DAY_WARNING_ENABLED and not no_warnings and max_date >= today:
            logger.warning(
                f"Your selected date range includes today ({today.isoformat()}). "
                f"EPSS scores for today might not be published yet or might be incomplete. "
                f"You may want to run this after the daily EPSS file has been posted."
            )
            if input("Continue? [y/N] ").lower() != 'y':
                logger.info("Download aborted by user")
                return
        
        # Collect files that need to be downloaded
        pending_downloads = []
        for date in self.iter_dates(min_date, max_date):
            path = get_file_path(
                workdir=workdir,
                file_format=self.file_format,
                key=date.isoformat(),
            )
            if not os.path.exists(path):
                pending_downloads.append((date, path))
        
        if not pending_downloads:
            logger.debug("All scores have already been downloaded")
            return
        
        # Display warning for large downloads
        if DOWNLOAD_WARNING_ENABLED and not no_warnings and len(pending_downloads) > LARGE_DOWNLOAD_THRESHOLD:
            logger.warning(
                f"You're about to download {len(pending_downloads)} files from {DEFAULT_DOWNLOAD_URL_BASE}. "
                f"This may put significant load on their servers."
            )
            if input("Continue? [y/N] ").lower() != 'y':
                logger.info("Download aborted by user")
                return
        
        logger.info(f"Using download speed '{self.download_speed}': {self.max_concurrent_downloads} concurrent downloads, {self.batch_delay}s delay between batches")
        
        # Process in batches for more controlled downloading
        batches = list(util.iter_chunks(pending_downloads, self.max_concurrent_downloads))
        total_files = len(pending_downloads)
        completed = 0
        failed = 0
        
        for i, batch in enumerate(batches):
            logger.debug(f"Processing batch {i+1}/{len(batches)} ({len(batch)} files)")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_downloads) as executor:
                futures = {}
                for date, path in batch:
                    future = executor.submit(
                        self.download_scores_by_date,
                        workdir=workdir,
                        date=date,
                    )
                    futures[future] = date
                
                for future in concurrent.futures.as_completed(futures):
                    date = futures[future]
                    try:
                        success = future.result()
                        if success:
                            completed += 1
                            if completed % 10 == 0 or completed == total_files:
                                logger.info('Downloaded %d/%d files', completed, total_files)
                        else:
                            # If download_scores_by_date returns False, it's a permanent failure
                            failed += 1
                            if date not in self.missing_dates:
                                self.missing_dates.append(date)
                            logger.warning('Unable to download scores for %s (permanently unavailable)', date.isoformat())
                    except Exception as e:
                        failed += 1
                        if date not in self.missing_dates:
                            self.missing_dates.append(date)
                        logger.warning('Failed to download scores for %s: %s', date.isoformat(), e)
            
            # Apply delay between batches (except for the last batch)
            if i < len(batches) - 1 and self.batch_delay > 0:
                logger.debug(f"Waiting {self.batch_delay}s before next batch")
                time.sleep(self.batch_delay)
         
        if failed > 0:
            logger.warning("Download completed with %d/%d files unavailable", failed, total_files)
            missing_dates_str = ', '.join(d.isoformat() for d in sorted(self.missing_dates)[:10])
            if len(self.missing_dates) > 10:
                missing_dates_str += f" and {len(self.missing_dates) - 10} more"
            logger.warning("Missing dates: %s", missing_dates_str)
        else:
            logger.info("All downloads completed successfully")

    def download_scores_by_date(self, workdir: str, date: TIME) -> bool:
        """
        Download EPSS scores published on the specified date.
        Returns True if successful, False if the file is permanently unavailable.
        """
        date = util.parse_date(date)
        path = get_file_path(
            workdir=workdir, 
            file_format=self.file_format, 
            key=date.isoformat(),
        )
        if os.path.exists(path):
            logger.debug("Scores for %s have already been downloaded: %s", date.isoformat(), path)
            return True
        
        # Determine whether to use file download, API, or try both
        if self.data_source == DATA_SOURCE_FILE:
            return self._download_scores_from_file(workdir, date, path)
        elif self.data_source == DATA_SOURCE_API:
            return self._download_scores_from_api(workdir, date, path)
        elif self.data_source == DATA_SOURCE_FILE_API:
            # Try file download first, fallback to API if it fails
            result = self._download_scores_from_file(workdir, date, path)
            if not result:
                logger.info(f"File download failed for {date.isoformat()}, trying API as fallback")
                return self._download_scores_from_api(workdir, date, path)
            return result
        else:
            logger.error(f"Invalid data source: {self.data_source}")
            return False
    
    def _download_scores_from_file(self, workdir: str, date: datetime.date, path: str) -> bool:
        """
        Download EPSS scores from the file source.
        Returns True if successful, False if the file is permanently unavailable.
        """
        url = get_download_url(date, verify_tls=self.verify_tls, download_url_base=self.download_url_base)
        logger.debug('Downloading scores for %s from file source: %s -> %s', date.isoformat(), url, path)

        # Implement retry with exponential backoff
        retry_count = 0
        permanent_failure = False
        
        while retry_count <= DOWNLOAD_RETRY_COUNT:
            try:
                response = requests.get(url, verify=self.verify_tls, stream=True, timeout=DOWNLOAD_TIMEOUT)
                
                # Handle permanent failure HTTP status codes
                if response.status_code >= 400:
                    # Most 4xx/5xx are permanent failures for file downloads
                    # except for some codes like 429 (Too Many Requests) or 503 (Service Unavailable)
                    if response.status_code not in (429, 503):
                        permanent_failure = True
                        logger.warning(
                            'Data for %s is unavailable from file source (HTTP %d: %s)', 
                            date.isoformat(), 
                            response.status_code,
                            response.reason
                        )
                        return False
                
                response.raise_for_status()
                
                data = io.BytesIO(response.content)
                
                if date <= util.parse_date('2022-01-01'):
                    skip_rows = 0
                else:
                    skip_rows = 1
                    
                df = pl.read_csv(data, skip_rows=skip_rows)
                
                # Add date and epss_version columns
                epss_version = get_epss_version_for_date(date)
                df = df.with_columns(
                    date=date,
                    epss_version=epss_version,
                )
                
                util.write_dataframe(df=df, path=path)
                return True
            except (requests.RequestException, IOError) as e:
                retry_count += 1
                
                # Check for HTTP status codes that indicate permanent failure
                if hasattr(e, 'response') and e.response is not None and e.response.status_code >= 400:
                    if e.response.status_code not in (429, 503):
                        # This is a permanent failure, don't retry
                        permanent_failure = True
                        logger.warning(
                            'Data for %s is permanently unavailable from file source (HTTP %d: %s)', 
                            date.isoformat(), 
                            e.response.status_code,
                            e.response.reason
                        )
                        return False
                
                # Don't retry for permanent failures or if we've exceeded retry count
                if permanent_failure or retry_count > DOWNLOAD_RETRY_COUNT:
                    logger.error(
                        'Failed to download scores from file source for %s after %d attempts: %s', 
                        date.isoformat(), retry_count, e
                    )
                    
                    # Don't add to missing dates if we're going to try API fallback
                    if self.data_source != DATA_SOURCE_FILE_API:
                        if date not in self.missing_dates:
                            self.missing_dates.append(date)
                    return False
                else:
                    # Calculate exponential backoff delay
                    delay = DOWNLOAD_RETRY_DELAY * (2 ** (retry_count - 1))
                    logger.warning(
                        'Failed to download scores from file source for %s (attempt %d/%d): %s. Retrying in %d seconds...', 
                        date.isoformat(), retry_count, DOWNLOAD_RETRY_COUNT + 1, e, delay
                    )
                    time.sleep(delay)
        
        # If we've exhausted all retries
        return False

    def _download_scores_from_api(self, workdir: str, date: datetime.date, path: str) -> bool:
        """
        Download EPSS scores from the API source.
        Returns True if successful, False if API access fails.
        """
        logger.debug('Downloading scores for %s from API source', date.isoformat())
        
        # Calculate delay between API requests based on download speed
        request_delay = API_RATE_LIMITS[self.download_speed]['request_delay']
        
        try:
            # Start with offset 0 and continue paginating
            offset = 0
            all_records = []
            total_records = None
            
            while total_records is None or offset < total_records:
                # Wait to respect API rate limits
                if offset > 0:
                    time.sleep(request_delay)
                
                params = {
                    'date': date.isoformat(),
                    'limit': API_DEFAULT_LIMIT,
                    'offset': offset,
                    'pretty': 'false',
                    'envelope': 'true'
                }
                
                # Make API request with appropriate retries
                api_data = self._make_api_request(params)
                
                if not api_data:
                    logger.error(f"Failed to retrieve data from API for {date.isoformat()}")
                    if date not in self.missing_dates:
                        self.missing_dates.append(date)
                    return False
                
                # Extract total record count
                total_records = api_data.get('total')
                
                # Extract data records
                records = api_data.get('data', [])
                if not records:
                    break
                
                all_records.extend(records)
                logger.debug(f"Retrieved {len(records)} records from API (offset {offset}/{total_records})")
                
                # Update offset for next page
                offset += len(records)
                
                # If we got fewer records than requested, we're done
                if len(records) < API_DEFAULT_LIMIT:
                    break
            
            if not all_records:
                logger.warning(f"No records found in API for {date.isoformat()}")
                if date not in self.missing_dates:
                    self.missing_dates.append(date)
                return False
            
            # Convert API data to DataFrame
            df = pl.DataFrame(all_records)
            
            # Add epss_version column
            epss_version = get_epss_version_for_date(date)
            df = df.with_columns(
                epss_version=epss_version,
                date=date
            )
            
            # Ensure proper column names (API returns 'cve', 'epss', 'percentile', 'date')
            required_columns = ['cve', 'epss', 'percentile', 'date', 'epss_version']
            missing_columns = [col for col in required_columns if col not in df.columns]
            
            if missing_columns:
                logger.error(f"API response missing required columns: {missing_columns}")
                logger.debug(f"Available columns: {df.columns}")
                return False
            
            # Convert column types (API returns strings for numeric values)
            df = df.with_columns([
                pl.col('epss').cast(pl.Float64),
                pl.col('percentile').cast(pl.Float64)
            ])
            
            # Write to file
            util.write_dataframe(df=df, path=path)
            logger.info(f"Successfully downloaded {len(df)} EPSS scores from API for {date.isoformat()}")
            return True
            
        except Exception as e:
            logger.error(f"Error downloading scores from API for {date.isoformat()}: {str(e)}")
            if date not in self.missing_dates:
                self.missing_dates.append(date)
            return False
    
    def _make_api_request(self, params: Dict) -> Optional[Dict]:
        """
        Make a request to the EPSS API with retry logic.
        Returns the parsed JSON response or None if the request failed.
        """
        retry_count = 0
        
        while retry_count <= DOWNLOAD_RETRY_COUNT:
            try:
                response = requests.get(
                    API_BASE_URL,
                    params=params,
                    verify=self.verify_tls,
                    timeout=DOWNLOAD_TIMEOUT
                )
                
                # Handle permanent failure HTTP status codes 
                if response.status_code >= 400:
                    # Most 4xx are permanent failures for API
                    # except for 429 (Too Many Requests) and some 5xx (Service errors)
                    if response.status_code < 500 and response.status_code != 429:
                        logger.warning(
                            'API request failed with HTTP %d: %s', 
                            response.status_code,
                            response.reason
                        )
                        return None
                
                response.raise_for_status()
                return response.json()
            
            except (requests.RequestException, IOError, ValueError) as e:
                retry_count += 1
                
                # Check for HTTP errors that indicate permanent failures
                if hasattr(e, 'response') and e.response is not None:
                    if e.response.status_code < 500 and e.response.status_code != 429:
                        # Client errors (4xx) other than 429 are permanent
                        logger.warning(f"API request failed with permanent error: HTTP {e.response.status_code} {e.response.reason}")
                        return None
                
                if retry_count > DOWNLOAD_RETRY_COUNT:
                    logger.error(f"API request failed after {DOWNLOAD_RETRY_COUNT} retries: {str(e)}")
                    return None
                
                # Calculate exponential backoff delay
                delay = DOWNLOAD_RETRY_DELAY * (2 ** (retry_count - 1))
                logger.warning(
                    f"API request failed (attempt {retry_count}/{DOWNLOAD_RETRY_COUNT + 1}): {str(e)}. "
                    f"Retrying in {delay} seconds..."
                )
                time.sleep(delay)
        
        return None


@dataclass()
class PolarsClient(BaseClient):
    """
    A client for working with EPSS scores using Polars DataFrames.
    """
    # Add a new parameter to control memory usage
    max_memory_gb: Optional[float] = None
    
    def get_scores(
            self, 
            workdir: str,
            min_date: Optional[TIME] = None, 
            max_date: Optional[TIME] = None,
            query: Optional[Query] = None,
            drop_unchanged_scores: bool = True) -> pl.DataFrame:
        
        min_date, max_date = self.get_date_range(min_date, max_date)

        # This is necessary to avoid listing all scores at the beginning of the requested timeframe.
        if drop_unchanged_scores:
            min_date -= datetime.timedelta(days=-1)
        
        if min_date == max_date:
            try:
                return self.get_scores_by_date(workdir=workdir, date=min_date, query=query)
            except Exception as e:
                logger.warning(f"Failed to get scores for {min_date.isoformat()}: {e}")
                if min_date not in self.missing_dates:
                    self.missing_dates.append(min_date)
                return pl.DataFrame(schema={'date': pl.Date, 'cve': pl.Utf8, 'epss': pl.Float64, 'percentile': pl.Float64, 'epss_version': pl.Int64})
        
        # NEW: Process dates in smaller batches to conserve memory
        dates = list(self.iter_dates(min_date, max_date))
        all_dates_set = set(dates)
        
        # Determine batch size based on number of dates
        date_count = len(dates)
        
        # If we have many dates to process, use batching to avoid OOM
        if date_count > 30:  # Arbitrary threshold, adjust based on your environment
            logger.info(f"Processing {date_count} dates in batches to optimize memory usage")
            return self._get_scores_in_batches(workdir, dates, query, drop_unchanged_scores, all_dates_set)
        
        # Original processing for smaller date ranges
        resolver = functools.partial(
            self.get_scores_by_date_safe,
            workdir=workdir,
            query=query,
        )
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_downloads) as executor:
            # Use a list comprehension with immediate garbage collection instead of keeping all in memory
            dfs = []
            for df in executor.map(lambda date: resolver(date=date), dates):
                if df is not None and not df.is_empty():
                    dfs.append(df)
            
            if not dfs:
                logger.warning("No data available for the requested date range")
                return pl.DataFrame(schema={'date': pl.Date, 'cve': pl.Utf8, 'epss': pl.Float64, 'percentile': pl.Float64, 'epss_version': pl.Int64})
            
            if drop_unchanged_scores is False:
                # Memory-efficient concatenation with explicit cleanup
                try:
                    df = pl.concat(dfs)
                    # Clear the list to free memory
                    dfs = None
                except Exception as e:
                    logger.error(f"Error concatenating dataframes: {e}")
                    # If we run out of memory here, try processing in batches instead
                    return self._get_scores_in_batches(workdir, dates, query, drop_unchanged_scores, all_dates_set)
            else:
                if len(dfs) < 2:
                    return dfs[0] if dfs else pl.DataFrame(schema={'date': pl.Date, 'cve': pl.Utf8, 'epss': pl.Float64, 'percentile': pl.Float64, 'epss_version': pl.Int64})
                
                # Process changes in a memory-efficient way
                try:
                    first = get_changed_scores(dfs[0], dfs[1])
                    result_dfs = [first]
                    
                    # Process pairs one at a time
                    for a, b in util.iter_pairwise(dfs[1:]):
                        changed = get_changed_scores(a, b)
                        result_dfs.append(changed)
                    
                    df = pl.concat(result_dfs)
                    # Clear lists to free memory
                    dfs = None
                    result_dfs = None
                except Exception as e:
                    logger.error(f"Error processing changed scores: {e}")
                    # If we run out of memory here, try processing in batches instead
                    return self._get_scores_in_batches(workdir, dates, query, drop_unchanged_scores, all_dates_set)
            
            # Check for missing dates in the resulting dataset
            try:
                included_dates_set = set(df.select('date').unique().to_series().to_list())
                missing_dates_set = all_dates_set - included_dates_set
                
                if missing_dates_set:
                    missing_dates_list = sorted(list(missing_dates_set))
                    self.missing_dates.extend(missing_dates_list)
                    missing_dates_str = ', '.join(d.isoformat() for d in missing_dates_list[:10])
                    if len(missing_dates_list) > 10:
                        missing_dates_str += f" and {len(missing_dates_list) - 10} more"
                    logger.warning("Data is missing for %d date(s): %s", len(missing_dates_list), missing_dates_str)
                
                df = df.sort(by=['cve'], descending=True)
                df = df.sort(by=['date'], descending=False)
                return df
            except Exception as e:
                logger.error(f"Error in final processing: {e}")
                # If we run out of memory during final processing, return a new empty dataframe
                return pl.DataFrame(schema={'date': pl.Date, 'cve': pl.Utf8, 'epss': pl.Float64, 'percentile': pl.Float64, 'epss_version': pl.Int64})

    def _get_scores_in_batches(self, workdir, dates, query, drop_unchanged_scores, all_dates_set):
        """
        Process large date ranges in smaller batches to avoid memory issues.
        """
        # Define a reasonable batch size based on environment
        batch_size = 10  # Process 10 dates at a time
        batch_count = (len(dates) + batch_size - 1) // batch_size  # Ceiling division
        
        logger.info(f"Processing {len(dates)} dates in {batch_count} batches of {batch_size}")
        
        # Create a schema for empty dataframes
        schema = {'date': pl.Date, 'cve': pl.Utf8, 'epss': pl.Float64, 'percentile': pl.Float64, 'epss_version': pl.Int64}
        
        # Process each batch and combine results
        all_results = []
        for i in range(0, len(dates), batch_size):
            batch = dates[i:i+batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{batch_count} ({len(batch)} dates)")
            
            # Get scores for this batch
            batch_min_date = min(batch)
            batch_max_date = max(batch)
            
            # Use a separate function call to ensure memory is freed between batches
            batch_df = self._process_date_batch(
                workdir=workdir,
                min_date=batch_min_date,
                max_date=batch_max_date,
                query=query,
                drop_unchanged_scores=drop_unchanged_scores
            )
            
            if not batch_df.is_empty():
                all_results.append(batch_df)
            
            # Force garbage collection between batches
            import gc
            gc.collect()
        
        # Combine all batch results
        if not all_results:
            return pl.DataFrame(schema=schema)
        
        try:
            # Try to combine all results at once
            df = pl.concat(all_results)
            all_results = None  # Free memory
            
            # Check for missing dates in the final dataset
            included_dates_set = set(df.select('date').unique().to_series().to_list())
            missing_dates_set = all_dates_set - included_dates_set
            
            if missing_dates_set:
                missing_dates_list = sorted(list(missing_dates_set))
                self.missing_dates.extend(missing_dates_list)
                missing_dates_str = ', '.join(d.isoformat() for d in missing_dates_list[:10])
                if len(missing_dates_list) > 10:
                    missing_dates_str += f" and {len(missing_dates_list) - 10} more"
                logger.warning("Data is missing for %d date(s): %s", len(missing_dates_list), missing_dates_str)
            
            # Apply final sorting
            df = df.sort(by=['cve'], descending=True)
            df = df.sort(by=['date'], descending=False)
            return df
        
        except Exception as e:
            logger.error(f"Failed to combine batch results: {e}")
            
            # Emergency fallback: return just the first batch result if we can't combine
            if all_results:
                logger.warning("Returning partial results due to memory constraints")
                return all_results[0]
            else:
                return pl.DataFrame(schema=schema)

    def _process_date_batch(self, workdir, min_date, max_date, query, drop_unchanged_scores):
        """
        Process a small batch of dates - this function is called separately to ensure
        memory from one batch is released before processing the next batch.
        """
        resolver = functools.partial(
            self.get_scores_by_date_safe,
            workdir=workdir,
            query=query,
        )
        
        batch_dates = list(self.iter_dates(min_date, max_date))
        
        dfs = []
        # Process sequentially to better control memory usage
        for date in batch_dates:
            df = resolver(date=date)
            if df is not None and not df.is_empty():
                dfs.append(df)
        
        if not dfs:
            return pl.DataFrame(schema={
                'date': pl.Date, 'cve': pl.Utf8, 'epss': pl.Float64, 
                'percentile': pl.Float64, 'epss_version': pl.Int64
            })
        
        if drop_unchanged_scores is False or len(dfs) < 2:
            if len(dfs) == 1:
                return dfs[0]
            return pl.concat(dfs)
        
        # Process changed scores
        result_dfs = []
        first = get_changed_scores(dfs[0], dfs[1])
        result_dfs.append(first)
        
        for i in range(1, len(dfs)-1):
            changed = get_changed_scores(dfs[i], dfs[i+1])
            result_dfs.append(changed)
        
        return pl.concat(result_dfs)
    
    def get_scores_by_date_safe(
            self,
            workdir: str, 
            date: Optional[TIME] = None,
            query: Optional[Query] = None) -> Optional[pl.DataFrame]:
        """
        Safe version of get_scores_by_date that returns None instead of raising exceptions.
        """
        try:
            return self.get_scores_by_date(workdir=workdir, date=date, query=query)
        except Exception as e:
            date_obj = util.parse_date(date)
            logger.warning(f"Failed to get scores for {date_obj.isoformat()}: {e}")
            if date_obj not in self.missing_dates:
                self.missing_dates.append(date_obj)
            return None
        
    def get_scores_by_date(
            self,
            workdir: str, 
            date: Optional[TIME] = None,
            query: Optional[Query] = None) -> pl.DataFrame:
        
        date = util.parse_date(date)
        path = get_file_path(
            workdir=workdir,
            file_format=self.file_format,
            key=date.isoformat(),
        )
        if not os.path.exists(path):
            # Try to download, but handle case where download fails
            success = self.download_scores_by_date(workdir=workdir, date=date)
            if not success:
                # If we couldn't download, return an empty dataframe with the correct schema
                schema = {'date': pl.Date, 'cve': pl.Utf8, 'epss': pl.Float64, 'percentile': pl.Float64, 'epss_version': pl.Int64}
                return pl.DataFrame(schema=schema)
            
            if not os.path.exists(path):
                raise ValueError(f"Scores unexpectedly not downloaded for {date.isoformat()}")

        df = read_dataframe(path)
        if query:
            df = self.filter_scores(df, query)

        # Check if the dataframe contains a `cve` column
        if 'cve' not in df.columns:
            raise ValueError(f'The dataframe for {date.isoformat()} does not contain a `cve` column (columns: {df.columns})')

        # Use the following column order: date, cve, epss, percentile, epss_version
        if EPSS_VERSION not in df.columns:
            # Add version column if it doesn't exist (for backward compatibility with existing files)
            epss_version = get_epss_version_for_date(date)
            df = df.with_columns(epss_version=epss_version)
            
        df = df.select(['date', 'cve', 'epss', 'percentile', 'epss_version'])

        df = df.sort(by=['cve'], descending=True)
        df = df.sort(by=['date'], descending=False)
        return df
    
    def filter_scores(self, df: pl.DataFrame, query: Query) -> pl.DataFrame:
        min_date, max_date = self.get_date_range()
        df = df.filter(pl.col('date') >= min_date)
        df = df.filter(pl.col('date') <= max_date)

        if query.cve_ids:
            df = df.filter(pl.col('cve').str.contains('|'.join(query.cve_ids)))

        if query.min_epss:
            df = df.filter(pl.col('epss') >= query.min_epss)
        
        if query.max_epss:
            df = df.filter(pl.col('epss') <= query.max_epss)
        
        if query.min_percentile:
            df = df.filter(pl.col('percentile') >= query.min_percentile)
        
        if query.max_percentile:
            df = df.filter(pl.col('percentile') <= query.max_percentile)
        
        return df
    
    def iter_urls(
            self,
            min_date: Optional[TIME] = None,
            max_date: Optional[TIME] = None) -> Iterator[str]:
        
        min_date, max_date = self.get_date_range(min_date, max_date)
        for date in self.iter_dates(min_date, max_date):
            yield get_download_url(date, verify_tls=self.verify_tls, download_url_base=self.download_url_base)


def get_file_path(workdir: str, file_format: str, key: Union[datetime.date, str]) -> str:
    """
    File paths are constructed using the following pattern: {workdir}/{key}.{file_format}

    For example, if `workdir` is `/tmp/epss`, and `file_format` is `parquet`:

    - If partitioning by `date`: `/tmp/epss/2024-01-01.parquet`
    - If partitioning by `cve`: `/tmp/epss/CVE-2024-01-01.parquet`
    """
    workdir = util.realpath(workdir)
    if isinstance(key, datetime.date):
        key = key.isoformat()
    return os.path.join(workdir, f'{key}.{file_format}')


def get_download_url(
        date: Optional[TIME] = None, 
        verify_tls: bool = True, 
        download_url_base: str = DEFAULT_DOWNLOAD_URL_BASE) -> str:
    """
    Returns the URL for downloading EPSS scores for the specified date.
    
    If no date is provided, the URL for the latest EPSS scores is returned.

    The date can be provided as a string in ISO-8601 format (YYYY-MM-DD), a datetime.date, datetime.datetime, or a UNIX timestamp.
   
    Example download URL: 

    - https://epss.empiricalsecurity.com/epss_scores-2024-01-01.csv.gz
    
    Parameters:
        date: The date for which to get EPSS scores
        verify_tls: Whether to verify TLS certificates
        download_url_base: The base URL for downloading EPSS scores (default: https://epss.empiricalsecurity.com)
    """
    date = util.parse_date(date) if date else get_max_date(verify_tls=verify_tls, download_url_base=download_url_base)
    return f"{download_url_base}/epss_scores-{date.isoformat()}.csv.gz"


def get_epss_version_for_date(date: TIME) -> int:
    """
    Returns the EPSS version number for a given date.
    
    EPSS versions:
    - Version 1: 2021-04-14 to 2022-02-03
    - Version 2: 2022-02-04 to 2023-03-06
    - Version 3: 2023-03-07 to 2025-03-16
    - Version 4: 2025-03-17 onwards
    """
    date = util.parse_date(date)
    if date < util.parse_date(V2_RELEASE_DATE):
        return 1
    elif date < util.parse_date(V3_RELEASE_DATE):
        return 2
    elif date < util.parse_date(V4_RELEASE_DATE):
        return 3
    else:
        return 4


def get_min_date(
        include_v1_scores: bool = MODEL_VERSION_V1 in DEFAULT_MODEL_VERSIONS.split(','), 
        include_v2_scores: bool = MODEL_VERSION_V2 in DEFAULT_MODEL_VERSIONS.split(','),
        include_v3_scores: bool = MODEL_VERSION_V3 in DEFAULT_MODEL_VERSIONS.split(','),
        include_v4_scores: bool = MODEL_VERSION_V4 in DEFAULT_MODEL_VERSIONS.split(',')) -> datetime.date:
    """
    Returns the earliest publication date for EPSS scores under the specified model version constraints.
    
    If multiple model versions are enabled, returns the earliest release date among them.
    """
    # Get the earliest date from all enabled model versions
    min_dates = []
    
    if include_v1_scores:
        min_dates.append(get_epss_v1_min_date())
    
    if include_v2_scores:
        min_dates.append(get_epss_v2_min_date())
    
    if include_v3_scores:
        min_dates.append(get_epss_v3_min_date())
    
    if include_v4_scores:
        min_dates.append(get_epss_v4_min_date())
    
    if not min_dates:
        logger.warning('No model versions selected. Defaulting to V3.')
        return get_epss_v3_min_date()
    
    return min(min_dates)


def get_epss_v1_min_date() -> datetime.date:
    """
    Returns the earliest publication date for EPSS v1 scores.
    """
    return util.parse_date(V1_RELEASE_DATE)


def get_epss_v1_max_date() -> datetime.date:
    """
    Returns the latest publication date for EPSS v1 scores.
    """
    return get_epss_v2_min_date() - datetime.timedelta(days=1)


def get_epss_v2_min_date() -> datetime.date:
    """
    Returns the earliest publication date for EPSS v2 scores.
    """
    return util.parse_date(V2_RELEASE_DATE)


def get_epss_v2_max_date() -> datetime.date:
    """
    Returns the latest publication date for EPSS v2 scores.
    """
    return get_epss_v3_min_date() - datetime.timedelta(days=1)


def get_epss_v3_min_date() -> datetime.date:
    """
    Returns the earliest publication date for EPSS v3 scores.
    """
    return util.parse_date(V3_RELEASE_DATE)


def get_epss_v3_max_date(verify_tls: bool = True, download_url_base: str = DEFAULT_DOWNLOAD_URL_BASE) -> datetime.date:
    """
    Returns the latest publication date for EPSS v3 scores.
    
    If EPSS v4 is available, returns the day before EPSS v4 release date.
    Otherwise, returns the latest available date.
    """
    # Check if we've reached v4 release date
    today = datetime.date.today()
    v4_min_date = util.parse_date(V4_RELEASE_DATE)
    
    if today >= v4_min_date:
        # Return the day before v4 was released
        return v4_min_date - datetime.timedelta(days=1)
    
    # Otherwise get the latest date
    url = f"{download_url_base}/epss_scores-current.csv.gz"
    logger.debug("Resolving latest publication date for EPSS scores")

    try:
        response = requests.head(url, verify=verify_tls, allow_redirects=True)
        
        # Check if there's a redirect with a date
        if response.history and 'Location' in response.history[0].headers:
            location = response.history[0].headers["Location"]
            regex = r"(\d{4}-\d{2}-\d{2})"
            match = re.search(regex, location)
            if match:
                date = datetime.date.fromisoformat(match.group(1))
                logger.debug(f'EPSS scores were last published on {date.isoformat()}')
                return date
        
        # If we can't extract from redirect, try to get current date
        # This is a fallback that assumes scores are updated daily
        current_date = datetime.date.today()
        logger.warning(f'Could not extract publication date from response, using current date: {current_date.isoformat()}')
        return current_date
        
    except Exception as e:
        logger.error(f"Error determining max date: {e}")
        # Fallback to current date
        current_date = datetime.date.today()
        logger.warning(f'Using current date as fallback: {current_date.isoformat()}')
        return current_date


def get_epss_v4_min_date() -> datetime.date:
    """
    Returns the earliest publication date for EPSS v4 scores.
    """
    return util.parse_date(V4_RELEASE_DATE)


def get_epss_v4_max_date(verify_tls: bool = True, download_url_base: str = DEFAULT_DOWNLOAD_URL_BASE) -> datetime.date:
    """
    Returns the latest publication date for EPSS v4 scores.
    """
    # Check if we've reached v4 release date
    today = datetime.date.today()
    v4_min_date = util.parse_date(V4_RELEASE_DATE)
    
    if today < v4_min_date:
        # V4 is not yet released, return its release date
        logger.warning(f'EPSS v4 is not yet released. It will be available on {v4_min_date.isoformat()}')
        return v4_min_date
    
    # Get the latest date
    url = f"{download_url_base}/epss_scores-current.csv.gz"
    logger.debug("Resolving latest publication date for EPSS scores")

    try:
        response = requests.head(url, verify=verify_tls, allow_redirects=True)
        
        # Check if there's a redirect with a date
        if response.history and 'Location' in response.history[0].headers:
            location = response.history[0].headers["Location"]
            regex = r"(\d{4}-\d{2}-\d{2})"
            match = re.search(regex, location)
            if match:
                date = datetime.date.fromisoformat(match.group(1))
                logger.debug(f'EPSS scores were last published on {date.isoformat()}')
                return date
        
        # Fallback to current date
        current_date = datetime.date.today()
        logger.warning(f'Could not extract publication date from response, using current date: {current_date.isoformat()}')
        return current_date
        
    except Exception as e:
        logger.error(f"Error determining max date: {e}")
        # Fallback to current date
        current_date = datetime.date.today()
        logger.warning(f'Using current date as fallback: {current_date.isoformat()}')
        return current_date


def get_max_date(
        include_v1_scores: bool = MODEL_VERSION_V1 in DEFAULT_MODEL_VERSIONS.split(','),
        include_v2_scores: bool = MODEL_VERSION_V2 in DEFAULT_MODEL_VERSIONS.split(','),
        include_v3_scores: bool = MODEL_VERSION_V3 in DEFAULT_MODEL_VERSIONS.split(','),
        include_v4_scores: bool = MODEL_VERSION_V4 in DEFAULT_MODEL_VERSIONS.split(','),
        verify_tls: bool = True,
        download_url_base: str = DEFAULT_DOWNLOAD_URL_BASE) -> datetime.date:
    """
    Returns the latest publication date for EPSS scores under the specified model version constraints.
    
    If multiple model versions are enabled, returns the latest available date among them.
    """
    # Collect all max dates from enabled model versions
    max_dates = []
    
    if include_v1_scores:
        # V1 ends right before V2 starts
        if not include_v2_scores and not include_v3_scores and not include_v4_scores:
            max_dates.append(get_epss_v1_max_date())
    
    if include_v2_scores:
        # V2 ends right before V3 starts
        if not include_v3_scores and not include_v4_scores:
            max_dates.append(get_epss_v2_max_date())
    
    if include_v3_scores:
        # V3 continues to present (or until V4 if not included)
        if not include_v4_scores:
            max_dates.append(get_epss_v3_max_date(verify_tls, download_url_base))
    
    if include_v4_scores:
        # V4 continues to present
        max_dates.append(get_epss_v4_max_date(verify_tls, download_url_base))
    
    if not max_dates:
        logger.warning('No model versions selected. Defaulting to V3.')
        return get_epss_v3_max_date(verify_tls, download_url_base)
    
    return max(max_dates)


def get_date_range(
        include_v1_scores: bool = False,
        include_v2_scores: bool = False,
        include_v3_scores: bool = True,
        include_v4_scores: bool = False,
        verify_tls: bool = True,
        download_url_base: str = DEFAULT_DOWNLOAD_URL_BASE) -> Tuple[datetime.date, datetime.date]:
    """
    Resolve the earliest and latest publication dates for EPSS scores under the specified model version constraints.
    """
    min_date = get_min_date(
        include_v1_scores=include_v1_scores,
        include_v2_scores=include_v2_scores,
        include_v3_scores=include_v3_scores,
        include_v4_scores=include_v4_scores,
    )
    max_date = get_max_date(
        include_v1_scores=include_v1_scores,
        include_v2_scores=include_v2_scores,
        include_v3_scores=include_v3_scores,
        include_v4_scores=include_v4_scores,
        verify_tls=verify_tls,
        download_url_base=download_url_base,
    )
    return min_date, max_date


def read_dataframe(path: str, date: Optional[TIME] = None) -> pl.DataFrame:
    """
    To support transformations over time, it's important to include a `date` column in the dataframe.

    If the `date` column is missing and not explicitly provided, it must be possible to infer it from the filename. In such cases, the filename must contain a date in ISO-8601 format (YYYY-MM-DD) (e.g. epss_scores-2024-01-01.csv.gz).
    """
    df = util.read_dataframe(path)
    logger.debug('Read dataframe from %s (shape: %s, columns: %s)', path, df.shape, df.columns)

    if 'date' not in df.columns:
        if date:
            date = util.parse_date(date)
        else:
            date = util.get_date_from_filename(path)
            assert date is not None, "ISO-8601 date not found in filename (YYYY-MM-DD)"

        df = df.with_columns(date=date)
        
    # Add epss_version if missing (for backward compatibility)
    if EPSS_VERSION not in df.columns and 'date' in df.columns:
        # Use the first date in the dataframe to determine version
        first_date = df.select('date').row(0)[0]
        epss_version = get_epss_version_for_date(first_date)
        df = df.with_columns(epss_version=epss_version)

    return df


def get_changed_scores(a: pl.DataFrame, b: pl.DataFrame) -> pl.DataFrame:
    """
    Given two dataframes, `a` and `b`, this function returns a new dataframe containing only the rows where the `epss` column has changed.
    
    The dataframes are expected to have the following columns:
    - `date`: a date in ISO-8601 format
    - `cve`: a CVE ID (e.g. CVE-2021-1234)
    - `epss`: a floating point number representing the EPSS score for the CVE (e.g. 0.1234)
    """
    df = pl.concat([a, b])
    df = df.sort(by=['date', 'cve'])
    df = df.with_columns(
        prev_epss=pl.col('epss').shift().over('cve'),
    )
    df = df.with_columns(
        epss_change=pl.col('epss') - pl.col('prev_epss'),
    )
    df = df.filter(pl.col('epss_change') != 0)
    df = df.drop('prev_epss', 'epss_change')

    df = df.sort(by=['cve'], descending=True)
    df = df.sort(by=['date'], descending=False)
    return df
