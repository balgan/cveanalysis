import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import requests
import zipfile
import io
from datetime import datetime, date, timedelta
from termcolor import colored  # You may need to install this package

# Function to download and extract the JSON file
def download_extract_json(url):
    response = requests.get(url)
    response.raise_for_status()
    zipfile_bytes = io.BytesIO(response.content)
    with zipfile.ZipFile(zipfile_bytes, 'r') as zip_ref:
        json_file = zip_ref.namelist()[0]  # Assuming there is only one file in the zip
        json_data = zip_ref.read(json_file)
    return json.loads(json_data)

def create_dataframe(cve_items):
    records = []
    for item in cve_items:
        cve_id = item['cve']['CVE_data_meta']['ID']
        date = datetime.strptime(item['publishedDate'], "%Y-%m-%dT%H:%MZ").date()
        has_references = bool(item['cve']['references']['reference_data'])
        
        has_cpes = False
        for node in item.get('configurations', {}).get('nodes', []):
            if 'cpe_match' in node:
                has_cpes = True
                break
            for child in node.get('children', []):
                if 'cpe_match' in child:
                    has_cpes = True
                    break
            if has_cpes:
                break

        records.append((cve_id, date, not has_references, not has_cpes))
    return pd.DataFrame(records, columns=['CVE_ID', 'Date', 'NoReferences', 'NoCPEs'])

# URL to the NVD JSON zip file
url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.zip'

# Download and extract JSON data
data = download_extract_json(url)

# Create DataFrame
df = create_dataframe(data['CVE_Items'])

# Filter new CVEs for today
today = date.today()- timedelta(days=1)
df_today = df[df['Date'] == today]

# Create a new DataFrame for display purposes
df_display = df_today[['CVE_ID', 'NoCPEs', 'NoReferences']].copy()

# Convert boolean to PASS/FAIL for display
df_display['CPE Status'] = df_display['NoCPEs'].apply(lambda x: 'FAIL' if x else 'PASS')
df_display['Reference Status'] = df_display['NoReferences'].apply(lambda x: 'FAIL' if x else 'PASS')

# Drop the original boolean columns
df_display.drop(['NoCPEs', 'NoReferences'], axis=1, inplace=True)

# Function to print the DataFrame in terminal with color
def print_colored_table(df):
    # Determine column widths
    cve_id_width = max(df['CVE_ID'].apply(len).max(), len('CVE ID')) + 2
    status_width = max(len('CPE Status'), len('Reference Status')) + 2

    # Print the header
    print(f"Analyzing CVES for {today}")
    print(f"{'CVE ID'.ljust(cve_id_width)}{'CPE'.ljust(8)}{'References'.ljust(status_width)}")

    # Print each row
    for index, row in df.iterrows():
        cve_id = row['CVE_ID'].ljust(cve_id_width)
        
        # Determine CPE and Reference status
        cpe_status_text = 'PASS' if not row['NoCPEs'] else 'FAIL'
        ref_status_text = 'PASS' if not row['NoReferences'] else 'FAIL'

        # Apply color to the statuses
        cpe_status = colored(cpe_status_text, 'green' if cpe_status_text == 'PASS' else 'red').ljust(status_width)
        ref_status = colored(ref_status_text, 'green' if ref_status_text == 'PASS' else 'red').ljust(status_width)

        # Print the row
        print(f"{cve_id}{cpe_status}{ref_status.ljust(status_width)}")

if 'NoCPEs' in df_today.columns and 'NoReferences' in df_today.columns:
    print_colored_table(df_today)
else:
    print("The DataFrame does not have the required 'NoCPEs' or 'NoReferences' columns.")

