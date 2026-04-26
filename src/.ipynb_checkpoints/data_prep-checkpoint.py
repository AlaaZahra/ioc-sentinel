import pandas as pd
import numpy as np
import os
import glob

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("data", exist_ok=True)  # Creates the folder if it doesn't exist

def load_and_clean_data(data_folder="D:/digilians/queensUN/intelligent cybersecurity systems/project/Project/ioc_sentinel/data/"):
    """Load and clean CICIDS2017 dataset"""
    
    csv_files = glob.glob(os.path.join(data_folder, "*.csv"))
    
    if not csv_files:
        print("No CSV files found in data/ folder")
        return None
    
    print(f"Found {len(csv_files)} file(s)")
    
    dfs = []
    for file in csv_files:
        print(f"Loading: {os.path.basename(file)}")
        df = pd.read_csv(file, low_memory=False)
        dfs.append(df)
    
    data = pd.concat(dfs, ignore_index=True)
    print(f"Total rows: {len(data):,}")
    
    # Clean column names
    data.columns = data.columns.str.strip()
    
    # Remove infinite and null values
    data.replace([np.inf, -np.inf], np.nan, inplace=True)
    data.dropna(inplace=True)
    
    # Binary label: BENIGN = 0, Attack = 1
    data['Label'] = data['Label'].str.strip()
    data['Binary_Label'] = (data['Label'] != 'BENIGN').astype(int)
    
    print(f"\nClass distribution:")
    print(f"  BENIGN  : {(data['Binary_Label']==0).sum():,}")
    print(f"  Attacks : {(data['Binary_Label']==1).sum():,}")
    
    return data


def select_features(data):
    """Select relevant network flow features"""
    
    feature_cols = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets',
        'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Bwd Packet Length Max', 'Bwd Packet Length Min',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
        'Flow IAT Std', 'Fwd IAT Total', 'Bwd IAT Total',
        'Fwd PSH Flags', 'SYN Flag Count', 'RST Flag Count',
        'ACK Flag Count', 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward', 'Avg Fwd Segment Size',
        'Avg Bwd Segment Size'
    ]
    
    available = [f for f in feature_cols if f in data.columns]
    print(f"Features selected: {len(available)}")
    
    X = data[available]
    y = data['Binary_Label']
    
    return X, y, available


if __name__ == "__main__":
    data = load_and_clean_data()
    if data is not None:
        X, y, features = select_features(data)
        print(f"\nData ready!")
        print(f"  X shape: {X.shape}")
        print(f"  y shape: {y.shape}")
        
        X_save = X.copy()
        X_save['Label'] = y.values
        X_save.to_csv("data/cleaned_data.csv", index=False)
        print("Saved to data/cleaned_data.csv")