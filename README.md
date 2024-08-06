# convert_trivy_to_csv
---

Author: Carlos Aguilar

## Description
    This script formats the output of a trivy scan which used the command below,
    to remove all unicode and output the table into a csv format
    
    Shell:
        `trivy image --input <image:tag|filename.tar> > trivy-results.txt`

## Example

```bash
    python convert_trivy_to_csv.py --input input.txt --output output.csv
```
