"""
Example of using the EPSS CLI with different version selections.

Usage examples:

1. Include only v4 scores (latest model):
   poetry run epss --include-versions v4 scores -a 2024-03-17 --download

2. Include both v3 and v4 scores:
   poetry run epss --include-versions v3,v4 scores -a 2023-03-07 --download

3. Include all model versions:
   poetry run epss --include-versions all scores -a 2021-05-01 --download
   # This is the same as default behavior with no --include-versions option

4. Include only older v2 scores:
   poetry run epss --include-versions v2 scores -a 2022-02-04 --download

The version selection constrains the available date range. For example, 
specifying only v1 will only allow dates between 2021-04-14 and 2022-02-03.
"""
print("This is a documentation file only. Run the commands shown in the documentation.")
