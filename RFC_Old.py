
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
import openpyxl

df=pd.read_excel('phising-uci-dataset.xlsx')

# Defining Training and Testing Set for Classification

X= df[['having_IP_Address', 'URL_Length', 'Shortining_Service',
       'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
       'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
       'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
       'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
       'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
       'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
       'Google_Index', 'Links_pointing_to_page', 'Statistical_report']]

y=df['Result']

X_train, X_test, y_train, y_test = train_test_split(X,y, test_size=0.2, random_state = 42)

# Logistic Regression
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