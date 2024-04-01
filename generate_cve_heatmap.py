import json
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import requests
import zipfile
import io
from datetime import datetime
from datetime import date
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
        date = datetime.strptime(item['publishedDate'], "%Y-%m-%dT%H:%MZ").date()
        has_references = bool(item['cve']['references']['reference_data'])
        
        # Improved CPE check
        has_cpes = False
        for node in item.get('configurations', {}).get('nodes', []):
            if 'cpe_match' in node:
                has_cpes = True
                break
            # Also check within children of the node, if present
            for child in node.get('children', []):
                if 'cpe_match' in child:
                    has_cpes = True
                    break
            if has_cpes:
                break

        records.append((date, not has_references, not has_cpes))
    return pd.DataFrame(records, columns=['Date', 'NoReferences', 'NoCPEs'])


# Function to generate heatmap with custom annotations
def generate_heatmap(df_summary, value_column, total_column, filename_prefix, cmap):
    total_missing = df_summary[value_column].sum()
    total_cves = df_summary[total_column].sum()
    
    pivot_table = df_summary.pivot(index='WeekOfYear', columns='DayOfWeek', values=value_column).fillna(0).astype(int)
    annotations = pivot_table.astype(str) + "/" + df_summary.pivot(index='WeekOfYear', columns='DayOfWeek', values=total_column).fillna(0).astype(int).astype(str)
    
    plt.figure(figsize=(20, 12))
    sns.heatmap(pivot_table, cmap=cmap, linewidths=.5, annot=annotations, fmt='')
    
    # Create dynamic title including the total counts
    today_str = date.today().strftime("%Y-%m-%d")
    if "heatmap_total_cves" in filename_prefix:
        title = f"Today ({today_str}) there are {total_missing} CVEs"
    else:
        title = f"Today ({today_str}) there are {total_missing} CVEs missing {filename_prefix.split('_')[-1].upper()} out of a total {total_cves} CVEs published in 2024"
    plt.title(title)
    plt.tight_layout()

    #Save for github README dynamic updates
    filename = f"{filename_prefix}.png"
    plt.savefig(filename)
    plt.close()
    # Save the heatmap with a filename including the generation date
    filename = f"historical/{filename_prefix}_{today_str}.png"
    plt.savefig(filename)
    plt.close()
    return filename



# URL to the NVD JSON zip file
url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.zip'

# Download and extract JSON data
data = download_extract_json(url)

# Create DataFrame
df = create_dataframe(data['CVE_Items'])

# Count CVEs per day and add day/week information
end_date = datetime.now().date()
all_dates = pd.date_range(start='2024-01-01', end=end_date, freq='D')
df_summary = df.groupby('Date').agg(TotalCVEs=('Date', 'size'),
                                     NoReferences=('NoReferences', 'sum'),
                                     NoCPEs=('NoCPEs', 'sum')).reindex(all_dates, fill_value=0)
df_summary['Date'] = pd.to_datetime(df_summary.index)
df_summary['DayOfWeek'] = df_summary['Date'].dt.dayofweek
df_summary['WeekOfYear'] = df_summary['Date'].dt.isocalendar().week

filename_cves = generate_heatmap(df_summary, 'TotalCVEs', 'TotalCVEs', 'heatmap_total_cves', 'Blues')
filename_no_references = generate_heatmap(df_summary, 'NoReferences', 'TotalCVEs', 'heatmap_no_references', 'OrRd')
filename_no_cpes = generate_heatmap(df_summary, 'NoCPEs', 'TotalCVEs', 'heatmap_no_cpes', 'OrRd')

# Output paths to the saved heatmap images
heatmap_paths = {
    'total_cves': filename_cves,
    'no_references': filename_no_references,
    'no_cpes': filename_no_cpes
}
print(heatmap_paths)