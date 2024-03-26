# Objective
To identify malicious websites when provided a link. It is a phishing checker.

## Resources for datasets
Malicious URLs Data: https://sysnet.ucsd.edu/projects/url/

Current Training Data: https://archive.ics.uci.edu/dataset/327/phishing+websites

## Workflow steps
- [Preprocessing](#preprocessing)
- [Features to be used](#features)
- [Improving Dataset](#improving-dataset)
- [Removing Class Imbalance (current step)](#removing-class-imbalance)
- [Logistic Regression](#logistic-regression)
- [Other Classification algorithms](#other-classification-algorithms)

## Installation

1. Clone the repository.
   ```sh
   git clone https://github.com/RafaeSyed/Phishing-analysis.git

2. Install requirements. 
Note: While the requirements.txt contain a lot of libraries most are redundant. As long as you have a working environment, add pandas, numpy, seaborn, matplotlib, scipy, scikit-learn and you should be good.
To install directly from requirements:
    ```sh
    pip install -r requirements.txt

## Preprocessing
Being done in phishing_analysis.ipynb.

## Features
Features are going to be the same as the UCI dataset. Clear reasoning is mentioned and it looks good enough to predict if a website is malicious.

Information on features can be found here: https://archive.ics.uci.edu/dataset/327/phishing+websites

## Improving dataset
Another datset is to be added to the current UCI dataset (https://sysnet.ucsd.edu/projects/url/). This dataset contains 2.4 million URLs. We will extract the URLs and write code to map individual feature that we will be using from each URL to make a datapoint that we can append to our existing data. (Not necessary but fun)

## Preprocessing
Using uci training data to clean data to make it work with classification algorithms. Preprocessing is being done in phishing_analysis.ipynb

## Removing Class Imbalance
There are few positive instances of malicious links so data is skewed. Will have to try different techniques to remove the imbalance. Most probably going to use random sampling.

## Logistic Regression
Trying Logistic regression to see how well the model performs with the given features

## Other Classification Algorithms
Other algorithms to check further because LogReg is not very powerful and find a more robust algorithm (XGBoost)

### We will be segmenting the code to individual algorithms at the end and not using ipynb. The files will be made .py files. Install Jupyter Notebook extension on VS code until then to view code. Do not Commit any changes on the main branch, fork if you want to work on the repo. 