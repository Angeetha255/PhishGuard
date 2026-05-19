import pandas as pd

# Try reading with proper quoting and encoding
try:
    df = pd.read_csv("data/phishingdataset.csv", encoding="utf-8", on_bad_lines="skip")
except:
    df = pd.read_csv("data/phishingdataset.csv", encoding="latin1", on_bad_lines="skip")

print("Dataset shape:", df.shape)
print("Columns:", df.columns)

# Keep only URL and Label columns if they exist
if "URL" in df.columns and "Label" in df.columns:
    df = df[["URL", "Label"]]

# Remove rows with null values
df = df.dropna()

# Keep only valid labels
df = df[df["Label"].isin(["bad", "good"])]

print("Cleaned shape:", df.shape)

# Save cleaned file
df.to_csv("data/clean_phishing_dataset.csv", index=False)

print("Clean dataset saved as clean_phishing_dataset.csv")