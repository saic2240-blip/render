import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

# ─────────────────────────────────────────────
# LOAD DATASET
# ─────────────────────────────────────────────
CSV_FILE = "02-14-2018.csv"

if not os.path.exists(CSV_FILE):
    print(f"[ERROR] Dataset not found: {CSV_FILE}")
    print("Download from: https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv")
    exit(1)

print(f"[1/5] Loading dataset: {CSV_FILE}")
df = pd.read_csv(CSV_FILE, low_memory=False)
print(f"      Rows loaded: {len(df):,}")

# ─────────────────────────────────────────────
# STRIP COLUMN WHITESPACE  ← critical for this dataset
# ─────────────────────────────────────────────
df.columns = df.columns.str.strip()
print(f"      Columns (first 10): {list(df.columns[:10])}")

# ─────────────────────────────────────────────
# CLEAN DATA
# ─────────────────────────────────────────────
print("[2/5] Cleaning data...")
df = df.replace([float('inf'), float('-inf')], 0)
df = df.dropna()
df = df.drop_duplicates()
print(f"      Rows after cleaning: {len(df):,}")

# ─────────────────────────────────────────────
# ENCODE LABELS  (0 = Benign, 1 = Attack)
# ✅ FIX 1: This dataset uses 'Benign' not 'BENIGN'
#    Labels in 02-14-2018.csv: 'Benign', 'FTP-BruteForce', 'SSH-Bruteforce'
# ─────────────────────────────────────────────
print("[3/5] Encoding labels...")
df['Label'] = df['Label'].str.strip()
print(f"      Label values found: {df['Label'].unique()}")  # sanity check

df['Label'] = df['Label'].apply(lambda x: 0 if x == 'Benign' else 1)
print(f"      Benign:  {(df['Label']==0).sum():,}")
print(f"      Attacks: {(df['Label']==1).sum():,}")

# ─────────────────────────────────────────────
# SELECT FEATURES
# ✅ FIX 2: This dataset uses 'Tot Fwd Pkts' not 'Total Fwd Packets'
# ─────────────────────────────────────────────
FEATURES = ['Flow Duration', 'Tot Fwd Pkts']

missing = [f for f in FEATURES if f not in df.columns]
if missing:
    print(f"\n[ERROR] Missing columns: {missing}")
    print(f"        Available columns: {list(df.columns)}")
    exit(1)

# Force numeric — mixed types exist in this dataset
for f in FEATURES:
    df[f] = pd.to_numeric(df[f], errors='coerce').fillna(0)

# ─────────────────────────────────────────────
# SAMPLE  (keep training fast)
# ─────────────────────────────────────────────
SAMPLE_SIZE = min(50000, len(df))
df_sample = df.sample(n=SAMPLE_SIZE, random_state=42)
X = df_sample[FEATURES]
y = df_sample['Label']
print(f"\n[4/5] Training on {SAMPLE_SIZE:,} samples | features: {FEATURES}")

# ─────────────────────────────────────────────
# TRAIN / TEST SPLIT + FIT MODEL
# ─────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# ─────────────────────────────────────────────
# EVALUATE
# ─────────────────────────────────────────────
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\n      Accuracy: {acc*100:.2f}%")
print("\n" + classification_report(y_test, y_pred, target_names=['Benign', 'Attack']))

# ─────────────────────────────────────────────
# SAVE MODEL
# ─────────────────────────────────────────────
print("[5/5] Saving model to model.pkl ...")
pickle.dump(model, open("model.pkl", "wb"))
print("\n✅  model.pkl created successfully!")
print("    You can now run:  python app.py")
