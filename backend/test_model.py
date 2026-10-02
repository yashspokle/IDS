import pandas as pd
import joblib

from sklearn.metrics import accuracy_score, classification_report

model = joblib.load("model.pkl")

features = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

columns = features + ["label", "difficulty"]

df = pd.read_csv(
    "../dataset/KDDTest+.txt",
    names=columns
)

def classify_attack(label):

    if label == "normal":
        return "Normal"

    if label in [
        "back", "land", "neptune",
        "pod", "smurf", "teardrop"
    ]:
        return "DoS"

    if label in [
        "ipsweep", "nmap",
        "portsweep", "satan"
    ]:
        return "Probe"

    if label in [
        "ftp_write", "guess_passwd",
        "warezclient", "warezmaster"
    ]:
        return "R2L"

    return "U2R"


df["label"] = df["label"].str.replace(".", "", regex=False)
df["label"] = df["label"].apply(classify_attack)

X = df[features]
y = df["label"]

predictions = model.predict(X)

print("\nAccuracy:")
print(accuracy_score(y, predictions))

print("\nClassification Report:")
print(classification_report(y, predictions))