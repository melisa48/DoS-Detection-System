import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import random
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns

def generate_sample_data(sample_size=10000, attack_ratio=0.2):
    data = []
    start_time = datetime.now()
    for i in range(sample_size):
        is_attack = random.random() < attack_ratio
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        data.append({
            'src_ip': src_ip,
            'dst_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': random.randint(80, 8080),
            'length': random.randint(64, 1500) * (5 if is_attack else 1),
            'flags': random.randint(0, 63),
            'time': (start_time + timedelta(seconds=random.uniform(0, 3600))).timestamp(),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'is_attack': int(is_attack)
        })
    return pd.DataFrame(data)

def extract_features(df):
    df['timestamp'] = pd.to_datetime(df['time'], unit='s')
    grouped = df.groupby('src_ip')
    
    def safe_rate(group):
        time_diff = (group['timestamp'].max() - group['timestamp'].min()).total_seconds()
        return group['length'].count() / max(time_diff, 1)
    
    packet_rates = grouped.apply(safe_rate, include_groups=False)
    byte_rates = grouped.apply(lambda x: x['length'].sum() / max((x['timestamp'].max() - x['timestamp'].min()).total_seconds(), 1), include_groups=False)
    
    df['packet_rate'] = df['src_ip'].map(packet_rates)
    df['byte_rate'] = df['src_ip'].map(byte_rates)
    df['avg_packet_size'] = grouped['length'].transform('mean')
    df['packet_size_std'] = grouped['length'].transform('std')
    
    df['flags'] = df['flags'].apply(lambda x: str(x))
    flags_dummies = pd.get_dummies(df['flags'], prefix='flag')
    protocol_dummies = pd.get_dummies(df['protocol'], prefix='protocol')
    df = pd.concat([df, flags_dummies, protocol_dummies], axis=1)
    
    return df

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [10, 20, None],
        'min_samples_split': [2, 5, 10]
    }
    
    grid_search = GridSearchCV(RandomForestClassifier(random_state=42), param_grid, cv=3, n_jobs=-1)
    grid_search.fit(X_train_scaled, y_train)
    
    print("Best parameters:", grid_search.best_params_)
    model = grid_search.best_estimator_
    
    y_pred = model.predict(X_test_scaled)
    print("Model Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10,7))
    sns.heatmap(cm, annot=True, fmt='d')
    plt.title('Confusion Matrix')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.show()
    
    feature_importance = pd.DataFrame({'feature': X.columns, 'importance': model.feature_importances_})
    feature_importance = feature_importance.sort_values('importance', ascending=False).head(10)
    plt.figure(figsize=(10,7))
    sns.barplot(x='importance', y='feature', data=feature_importance)
    plt.title('Top 10 Feature Importances')
    plt.show()
    
    return model, scaler

def detect_dos(model, scaler, traffic_data):
    features_scaled = scaler.transform(traffic_data)
    predictions = model.predict(features_scaled)
    return "DoS Attack Detected" if any(predictions == 1) else "Normal Traffic"

if __name__ == "__main__":
    print("Generating and preprocessing data...")
    df = generate_sample_data()
    df = extract_features(df)
    
    features = ['packet_rate', 'byte_rate', 'avg_packet_size', 'packet_size_std'] + \
               [col for col in df.columns if col.startswith(('flag_', 'protocol_'))]
    X = df[features]
    y = df['is_attack']
    
    print("Training model...")
    model, scaler = train_model(X, y)
    
    print("\nSimulating real-time detection...")
    new_traffic = df.sample(n=100)
    result = detect_dos(model, scaler, new_traffic[features])
    print(result)