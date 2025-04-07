from epss.client import PolarsClient
import logging

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(message)s')

# Test different version combinations
def test_version(description, v1=False, v2=False, v3=False, v4=False):
    print(f"\n{description}:")
    client = PolarsClient(
        include_v1_scores=v1,
        include_v2_scores=v2,
        include_v3_scores=v3,
        include_v4_scores=v4
    )
    min_date, max_date = client.get_date_range()
    print(f"Date range: {min_date} to {max_date}")
    
    # List which versions are enabled
    versions = []
    if v1: versions.append("v1")
    if v2: versions.append("v2")
    if v3: versions.append("v3")
    if v4: versions.append("v4")
    print(f"Enabled versions: {', '.join(versions)}")

# Test all combinations
test_version("1. Default (v1, v2, v3)", v1=True, v2=True, v3=True)
test_version("2. Only v1", v1=True)
test_version("3. Only v2", v2=True)
test_version("4. Only v3", v3=True)
test_version("5. v1 and v2", v1=True, v2=True)
test_version("6. v2 and v3", v2=True, v3=True)
test_version("7. All versions", v1=True, v2=True, v3=True, v4=True)
