# CVE Analysis Dashboard 📊 - UPDATED DAILY

## Introduction

This project is dedicated to analyzing and visualizing Common Vulnerabilities and Exposures (CVE) data 🛡️. It focuses on identifying CVEs by their publication date, and whether they're missing Common Platform Enumerations (CPEs) or references.

## Features

- **Data Extraction**: Automatically downloads CVE data from the NVD feeds.
- **Data Processing**: Parses the JSON data to identify CVEs with/without CPEs and references.
- **Visualization**: Generates daily and weekly heatmap visualizations to provide insights at a glance.
- **Reporting**: Creates a detailed analysis report of CVE trends over time.

## Heatmaps 🔥

The generated heatmaps include:

1. **Total CVEs Per Day**: Shows the total count of new CVEs reported each day.
   ![Total CVEs Per Day Heatmap](heatmap_total_cves.png)
2. **CVEs Without References**: Indicates the number of CVEs lacking references on a daily basis.
   ![CVEs Without References Heatmap](heatmap_no_references.png)
3. **CVEs Without CPEs**: Highlights the daily CVEs that are missing CPEs.
   ![CVEs Without CPEs Heatmap](heatmap_no_cpes.png)
4. **Median and Mean EPSS scores**: Monitor EPSS for changes overtime.
   ![EPSS mean and median](epss_mean_median.png)
5. **EPSS for CISA KEV added after 2023**: Keeping track of EPSS on CISA KEV
   ![EPSS CISA KEV](heatmap_cisa_kev_epss.png)
5. **CVSS for CISA KEV added after 2023**: Keeping track of EPSS on CISA KEV
   ![EPSS CISA KEV](heatmap_cisa_kev_cvss.png)


## Usage

To generate the heatmaps:

```bash
python generate_cve_heatmap.py
