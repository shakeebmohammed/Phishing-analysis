
import utils
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import sklearn
from sklearn import metrics
import shap
from sklearn.ensemble import RandomForestClassifier
import numpy as np

df=pd.read_csv('URLs.csv')

# Defining Training and Testing Set for Classification

X= df[['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
       'https_Domain', 'TinyURL', 'Prefix/Suffix']]

y=df['Label']

X_train, X_test, y_train, y_test = train_test_split(X,y, test_size=0.2, random_state = 42)

# Random Forest Classifier
rfc = RandomForestClassifier(random_state=42)
rfc.fit(X_train, y_train)
y_rfc_pred = rfc.predict(X_test)

cnf_matrix = metrics.confusion_matrix(y_test, y_rfc_pred)
cnf_matrix

target_names = ['Not phishing', 'Phishing']
print(classification_report(y_test, y_rfc_pred, target_names=target_names))

# Calculate ROC curve and AUC
fpr, tpr, _ = metrics.roc_curve(y_test, y_rfc_pred, pos_label=1)
auc = metrics.roc_auc_score(y_test, y_rfc_pred)

# Plot ROC curve
# Convert AUC value to string before concatenating
plt.plot(fpr, tpr, label="data 1, auc=" + str(auc))

plt.legend(loc=4)
plt.show()
