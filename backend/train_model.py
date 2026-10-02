import pandas as pd
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report


FEATURES = [
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

COLUMNS = FEATURES + ["label", "difficulty"]


def family(label):

    if label == "normal":
        return "Normal"

    dos = [
        "back", "land", "neptune", "pod",
        "smurf", "teardrop", "mailbomb",
        "processtable", "udpstorm", "worm"
    ]

    probe = [
        "ipsweep", "nmap", "portsweep",
        "satan", "mscan", "saint"
    ]

    r2l = [
        "ftp_write", "guess_passwd", "imap",
        "multihop", "phf", "spy",
        "warezclient", "warezmaster",
        "httptunnel", "named", "sendmail",
        "snmpgetattack", "snmpguess",
        "xlock", "xsnoop"
    ]

    u2r = [
        "buffer_overflow", "loadmodule",
        "perl", "rootkit", "ps",
        "sqlattack", "xterm"
    ]

    if label in dos:
        return "DoS"

    if label in probe:
        return "Probe"

    if label in r2l:
        return "R2L"

    if label in u2r:
        return "U2R"

    return "Normal"


print("Loading dataset...")

train = pd.read_csv(
    "../dataset/KDDTrain+.txt",
    names=COLUMNS
)

test = pd.read_csv(
    "../dataset/KDDTest+.txt",
    names=COLUMNS
)

train["label"] = train["label"].str.replace(".", "", regex=False)
test["label"] = test["label"].str.replace(".", "", regex=False)

train["label"] = train["label"].apply(family)
test["label"] = test["label"].apply(family)

X_train = train[FEATURES]
y_train = train["label"]

X_test = test[FEATURES]
y_test = test["label"]

categorical = [
    "protocol_type",
    "service",
    "flag"
]

preprocessor = ColumnTransformer([
    (
        "categorical",
        OneHotEncoder(handle_unknown="ignore"),
        categorical
    )
], remainder="passthrough")

model = Pipeline([
    ("preprocessor", preprocessor),
    (
        "classifier",
        RandomForestClassifier(
            n_estimators=150,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        )
    )
])

print("Training model...")

model.fit(X_train, y_train)

print("Testing model...")

predictions = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, predictions))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)

joblib.dump(model, "model.pkl")

print("\nModel saved successfully.")