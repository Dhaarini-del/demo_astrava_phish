import pandas as pd
import joblib

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# -----------------------------
# STEP 1: Load Dataset
# -----------------------------
data = pd.read_csv("phishing_dataset.csv")

print("Dataset loaded successfully")
print("Columns:\n", data.columns)


# -----------------------------
# STEP 2: Split Features & Label
# -----------------------------
X = data.drop("CLASS_LABEL", axis=1)
y = data["CLASS_LABEL"]

print("\nFeature shape:", X.shape)
print("Label shape:", y.shape)


# -----------------------------
# STEP 3: Train Test Split
# (Stratified keeps class balance)
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining size:", X_train.shape)
print("Testing size:", X_test.shape)


# -----------------------------
# STEP 4: Hyperparameter Tuning
# -----------------------------
print("\nTuning Random Forest...")

param_grid = {
    "n_estimators": [200, 300],
    "max_depth": [None, 10, 20],
    "min_samples_split": [2, 5],
    "min_samples_leaf": [1, 2]
}

rf = RandomForestClassifier(
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

grid_search = GridSearchCV(
    rf,
    param_grid,
    cv=3,
    scoring="accuracy",
    n_jobs=-1,
    verbose=2
)

grid_search.fit(X_train, y_train)

model = grid_search.best_estimator_

print("\nBest Parameters:")
print(grid_search.best_params_)


# -----------------------------
# STEP 5: Evaluate Model
# -----------------------------
print("\nEvaluating model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:\n")
print(confusion_matrix(y_test, y_pred))


# -----------------------------
# STEP 6: Feature Importance
# -----------------------------
importance = pd.Series(model.feature_importances_, index=X.columns)
importance = importance.sort_values(ascending=False)

print("\nTop 10 Important Features:\n")
print(importance.head(10))


# -----------------------------
# STEP 7: Save Model
# -----------------------------
joblib.dump(model, "url_phishing_model.pkl")

print("\nModel saved successfully as url_phishing_model.pkl")