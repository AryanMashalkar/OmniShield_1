import pandas as pd

print('Loading 2.8M row CSV (takes ~10s)...')
df = pd.read_csv(r'A:\OmniShield\cic_ids2017.csv')

label_col = [c for c in df.columns if 'label' in c.lower()][0]

benign = df[df[label_col].astype(str).str.strip().str.upper() == 'BENIGN'].sample(n=30000, random_state=42)
attacks = df[df[label_col].astype(str).str.strip().str.upper() != 'BENIGN'].sample(n=20000, random_state=42)

demo_df = pd.concat([benign, attacks]).sample(frac=1, random_state=42)
demo_df.to_csv(r'A:\OmniShield\cic_demo.csv', index=False)
print('? DONE! Saved clean 50k-row slice to A:\OmniShield\cic_demo.csv')
