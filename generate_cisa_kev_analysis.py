import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import os
import requests
import pandas as pd
import zipfile
import io
import json
from datetime import datetime

#This is based on date added to CISA KEV not on the CVE ID
date_to_start = "2023-01-01"

def download_kev_csv(url, save_dir='cisa_data', filename='known_exploited_vulnerabilities.csv'):
    os.makedirs(save_dir, exist_ok=True)
    file_path = os.path.join(save_dir, filename)
    response = requests.get(url)
    if response.status_code == 200:
        with open(file_path, 'wb') as f:
            f.write(response.content)
        print(f"File downloaded successfully: {file_path}")
    else:
        print(f"Failed to download file. Status code: {response.status_code}")

def load_kev_data():
    kev_csv_path = "cisa_data/known_exploited_vulnerabilities.csv"
    df = pd.read_csv(kev_csv_path)
    df['dateAdded'] = pd.to_datetime(df['dateAdded'])
    return df[df['dateAdded'] > date_to_start]

def collect_max_epss_scores(kev_df, epss_data_dir):
    latest_file = max([os.path.join(epss_data_dir, file) for file in os.listdir(epss_data_dir) if file.endswith(".csv.gz")], key=os.path.getctime)
    df = pd.read_csv(latest_file, compression='gzip', skiprows=1, names=['cve', 'epss_score', 'percentile'])
    df['epss_score'] = pd.to_numeric(df['epss_score'], errors='coerce')
    
    max_scores = {}
    for cve in kev_df['cveID']:
        if cve in df['cve'].values:
            max_scores[cve] = df.loc[df['cve'] == cve, 'epss_score'].max()
            print(f"Max score for : {cve} is {max_scores[cve]}")
        else:
            max_scores[cve] = 0
    return max_scores


def plot_heatmap_kev_epss(max_scores, output_file='heatmap_cisa_kev_epss.png'):
    cve_ids = sorted(max_scores)
    scores = [max_scores[cve] if max_scores[cve] is not None else np.nan for cve in cve_ids]
    
    # Calculate dimensions of the square matrix
    size = int(np.ceil(np.sqrt(len(scores))))
    figsize_factor = 2
    figsize = (size * figsize_factor, size * figsize_factor)
    
    total_elements = size**2
    padding = [np.nan] * (total_elements - len(scores))  # Pad scores with NaN
    cve_padding = [''] * (total_elements - len(cve_ids))  # Pad labels with empty strings
    scores.extend(padding)
    cve_ids.extend(cve_padding)
    
    scores_array = np.array(scores).reshape((size, size))
    labels_array = np.array(cve_ids).reshape((size, size))

    # Set vmin and vmax for the color scale based on your actual data range
    vmin = 0  # or set to min(scores) if you expect values below zero
    vmax = 1  # or set to max(scores) for your data range

    plt.figure(figsize=figsize)
    sns.heatmap(scores_array, annot=labels_array, fmt="", cmap='OrRd', cbar=True, vmin=vmin, vmax=vmax)
    plt.title(f'Heatmap of Max EPSS Scores for KEV CVEs added after {date_to_start}', fontsize=20)
    plt.axis('off')
    
    plt.savefig(output_file, bbox_inches='tight', dpi=300)
    plt.close()


def generate_time_series(kev_df, epss_data_dir):
    # Create a set of CVE IDs from KEV for fast lookup
    kev_cve_ids = set(kev_df['cveID'])
    
    # Pre-load relevant EPSS data into a single DataFrame
    all_epss_data = pd.DataFrame()
    for file in sorted(os.listdir(epss_data_dir)):
        if file.endswith(".csv.gz"):
            file_path = os.path.join(epss_data_dir, file)
            print(f"Loading into memory {file_path}")
            df = pd.read_csv(file_path, compression='gzip', skiprows=1, names=['cve', 'epss_score', 'percentile'])
            df['date'] = pd.to_datetime(file.replace('epss_scores-', '').replace('.csv.gz', ''))
            df = df[df['cve'].isin(kev_cve_ids)]  # Filter only relevant CVEs
            all_epss_data = pd.concat([all_epss_data, df], ignore_index=True)

    # Convert epss_score to numeric across all data
    all_epss_data['epss_score'] = pd.to_numeric(all_epss_data['epss_score'], errors='coerce')

    # Generate time series for each CVE in KEV
    for index, row in kev_df.iterrows():
        cve_id = row['cveID']
        date_added = pd.to_datetime(row['dateAdded'])
        output_dir = "EPSS_KEV"
        os.makedirs(output_dir, exist_ok=True)

        plt.figure(figsize=(12, 6))
        cve_data = all_epss_data[all_epss_data['cve'] == cve_id]
        
        plt.scatter(cve_data['date'], cve_data['epss_score'], color='blue', label=f'EPSS Scores for {cve_id}')
        plt.axvline(x=date_added, color='red', linestyle='--', label='Added to KEV')
        plt.title(f"Time Series for {cve_id}")
        plt.xlabel("Date")
        plt.ylabel("EPSS Score")
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(output_dir, f"{cve_id}_timeseries.png"))
        plt.close()


# Function to download and extract the JSON file from NVD
def download_extract_jsons(start_year=2002, end_year=2024):
    cvss_records = []
    for year in range(start_year, end_year + 1):
        url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'
        print(f'Downloading NVD - {url}')
        response = requests.get(url)
        if response.ok:
            zipfile_bytes = io.BytesIO(response.content)
            with zipfile.ZipFile(zipfile_bytes, 'r') as zip_ref:
                json_file = zip_ref.namelist()[0]
                json_data = json.loads(zip_ref.read(json_file))
                for item in json_data['CVE_Items']:
                    cve_id = str(item['cve']['CVE_data_meta']['ID'])
                    cvss_score = item['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0)
                    cvss_records.append((cve_id, cvss_score))
        else:
            print(f"Failed to download data for {year}")
    return cvss_records

def create_dataframe(cve_items):
    records = [(cve_id, cvss_score) for cve_id, cvss_score in cve_items]
    return pd.DataFrame(records, columns=['CVE_ID', 'CVSS_Score'])

def merge_kev_with_cvss(df_kev, df_cvss):
    df_kev['cveID'] = df_kev['cveID'].astype(str)
    df_cvss['CVE_ID'] = df_cvss['CVE_ID'].astype(str)
    df_cvss = df_cvss.groupby('CVE_ID').max().reset_index()  # Taking the maximum CVSS score
    merged_df = pd.merge(df_kev, df_cvss, how='left', left_on='cveID', right_on='CVE_ID')
    merged_df['CVSS_Score'].fillna(0, inplace=True)
    return merged_df

def plot_heatmap_cvss(cvss_scores, output_file='heatmap_cisa_kev_cvss.png'):
    cve_ids = sorted(cvss_scores)
    scores = [cvss_scores[cve] for cve in cve_ids]
    size = int(np.ceil(np.sqrt(len(scores))))
    figsize_factor = 2
    figsize = (size * figsize_factor, size * figsize_factor)
    total_elements = size**2
    padding = [0] * (total_elements - len(scores))
    cve_padding = [''] * (total_elements - len(cve_ids))
    scores.extend(padding)
    cve_ids.extend(cve_padding)
    scores_array = np.array(scores).reshape((size, size))
    labels_array = np.array(cve_ids).reshape((size, size))
    plt.figure(figsize=figsize)
    sns.heatmap(scores_array, annot=labels_array, fmt="", cmap='OrRd', cbar=True)
    plt.title(f'Heatmap of CVSS Scores for KEV CVEs added after {date_to_start}', fontsize=20)
    plt.axis('off')
    plt.savefig(output_file, bbox_inches='tight', dpi=300)
    plt.close()


url_kev = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
download_kev_csv(url_kev)
epss_data_dir = "epss_data"
df_kev = load_kev_data()
max_scores = collect_max_epss_scores(df_kev, epss_data_dir)
print(len(max_scores))
plot_heatmap_kev_epss(max_scores)
#generate_time_series(df_kev, epss_data_dir)
url_kev = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
download_kev_csv(url_kev)
df_kev = load_kev_data()
cvss_records = download_extract_jsons()
df_cvss = create_dataframe(cvss_records)
df_merged = merge_kev_with_cvss(df_kev, df_cvss)
cvss_scores = {row['CVE_ID']: row['CVSS_Score'] for index, row in df_merged.iterrows()}
plot_heatmap_cvss(cvss_scores)