
import pandas as pd

# Load the phishing dataset
df = pd.read_csv("Data/phishing_site_urls.csv")

# Display first 5 records
print("\nFIRST 5 RECORDS:")
print(df.head())

# Display column names
print("\nCOLUMN NAMES:")
print(df.columns.tolist())

# Display total rows and columns
print("\nDATASET SIZE:")
print(df.shape)

# Display phishing and legitimate counts
print("\nLABEL DISTRIBUTION:")
print(df["Label"].value_counts())
