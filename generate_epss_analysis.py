import os
import pandas as pd
import requests
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta

# Define the date range for the data
start_date = datetime(2023, 1, 1)
end_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
filename_prefix = "epss_mean_median"

# Function to generate dates
def generate_date_range(start, end):
    delta = end - start
    return [start + timedelta(days=i) for i in range(delta.days + 1)]

# Function to download data
def download_epss_data(date, save_dir='epss_data'):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    date_str = date.strftime('%Y-%m-%d')
    url = f'https://epss.cyentia.com/epss_scores-{date_str}.csv.gz'
    save_path = os.path.join(save_dir, f'epss_scores-{date_str}.csv.gz')
    
    if not os.path.exists(save_path):
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(save_path, 'wb') as f:
                f.write(response.raw.read())
            print(f'Downloaded {save_path}')
        else:
            print(f'Failed to download data for {date_str}')
    else:
        print(f'File {save_path} already exists')

# Function to load and clean data
def load_and_clean_data(file_path):
    df = pd.read_csv(file_path, skiprows=1, names=['cve', 'epss_score', 'percentile'])
    df = df[df['epss_score'].apply(lambda x: isinstance(x, float) or x.replace('.', '', 1).isdigit())]
    df['epss_score'] = pd.to_numeric(df['epss_score'])
    return df

# Main analysis and plotting
def analyze_and_plot(data_dir='epss_data'):
    stats_over_time = {'date': [], 'mean_epss_score': [], 'median_epss_score': [], 'std_epss_score': []}

    for date in generate_date_range(start_date, end_date):
        date_str = date.strftime('%Y-%m-%d')
        file_path = os.path.join(data_dir, f'epss_scores-{date_str}.csv.gz')
        if os.path.exists(file_path):
            daily_data = load_and_clean_data(file_path)
            stats_over_time['date'].append(date)
            stats_over_time['mean_epss_score'].append(daily_data['epss_score'].mean())
            stats_over_time['median_epss_score'].append(daily_data['epss_score'].median())
            stats_over_time['std_epss_score'].append(daily_data['epss_score'].std())

    stats_df = pd.DataFrame(stats_over_time)
    
    # Plotting
    sns.set(style="whitegrid")
    plt.figure(figsize=(14, 6))

    plt.subplot(1, 2, 1)
    sns.lineplot(x='date', y='mean_epss_score', data=stats_df, marker='o')
    plt.title('Mean EPSS Score Over Time')
    plt.xticks(rotation=45)

    plt.subplot(1, 2, 2)
    sns.lineplot(x='date', y='median_epss_score', data=stats_df, marker='o', color='orange')
    plt.title('Median EPSS Score Over Time')
    plt.xticks(rotation=45)

    plt.tight_layout()
    filename = f"historical/{filename_prefix}_{end_date}.png"
    plt.savefig(filename)
    filename = f"{filename_prefix}.png"
    plt.savefig(filename)
    plt.close()

    

# Download the data
for date in generate_date_range(start_date, end_date):
    download_epss_data(date)

# Analyze and plot the data
analyze_and_plot()
