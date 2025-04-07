"""
Example of using the EPSS CLI with different version selections.

Usage examples:

1. Include only v3 scores:
   poetry run epss --include-versions v3 scores -a 2024-01-01 --download

2. Include both v2 and v3 scores:
   poetry run epss --include-versions v2,v3 scores -a 2023-01-01 --download

3. Include all model versions:
   poetry run epss --include-versions all scores -a 2021-05-01 --download

The version selection constrains the available date range. For example, 
specifying only v1 will only allow dates between 2021-04-14 and 2022-02-03.
"""
print("This is a documentation file only. Run the commands shown in the documentation.")
