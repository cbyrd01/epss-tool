from epss.client import PolarsClient
import logging

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')

# Test all versions (default)
print("\n1. Default behavior (all versions included):")
client = PolarsClient()
min_date, max_date = client.get_date_range()
print(f"Result: {min_date} to {max_date}")

# Test v3 only
print("\n2. Only v3 scores:")
v3_client = PolarsClient(include_v1_scores=False, include_v2_scores=False, include_v3_scores=True)
min_date, max_date = v3_client.get_date_range()
print(f"Result: {min_date} to {max_date}")

# Test date constraints
print("\n3. All versions but with min_date='2024-01-01':")
min_date, max_date = client.get_date_range(min_date='2024-01-01')
print(f"Result: {min_date} to {max_date}")

# Test v1 only
print("\n4. Only v1 scores:")
v1_client = PolarsClient(include_v1_scores=True, include_v2_scores=False, include_v3_scores=False)
min_date, max_date = v1_client.get_date_range()
print(f"Result: {min_date} to {max_date}")
