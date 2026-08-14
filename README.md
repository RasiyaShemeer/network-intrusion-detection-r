# Network Intrusion Detection Using Machine Learning in R

> **Academic project notice:** This repository documents an academic machine-learning project completed at Edith Cowan University. It is a comparative classification analysis and is **not** a deployed, production-ready cybersecurity or intrusion-detection system.

## Project overview

This project develops and evaluates machine-learning models in R for classifying Advanced Persistent Threat (APT) activity in the WACY-COM network dataset. The workflow covers data cleaning, feature transformation, model tuning, held-out testing, and automated export of performance metrics and visualisations.

## Objective

The objective was to compare regularised regression and ensemble tree methods for binary APT classification and determine which model provided the strongest balance of accuracy, sensitivity, specificity, and ROC-AUC.

## Dataset

The analysis uses 200,000 records from the WACY-COM network dataset, with `APT` as the binary target variable (`No` or `Yes`). After preprocessing and complete-case filtering, 183,009 observations remained for modelling.

The raw dataset is not included in this repository because its distribution may be subject to university or dataset licensing restrictions. Authorised users should place the file at:

```text
data/WACY-COM.csv
```

## Data preparation

The R workflow:

- removes invalid and sentinel values;
- excludes problematic or unsuitable variables;
- converts unknown operating-system values to missing values;
- consolidates selected categorical levels;
- applies log and square-root transformations to skewed numerical features;
- removes incomplete observations; and
- creates a reproducible 30% training and 70% held-out test split.

## Models compared

Three supervised classification models were evaluated:

1. **LASSO logistic regression** using `glmnet`, with 5-fold cross-validation across 20 lambda values and ROC-AUC as the tuning metric.
2. **Bagging trees** using `ipred` and `rpart`, tuned using out-of-bag error across combinations of the number of trees, complexity parameter, and minimum split size.
3. **Random Forest** using `ranger`, tuned using out-of-bag error across the number of trees, candidate variables per split, minimum node size, replacement sampling, and sampling fraction.

## Evaluation methods

Models were assessed on the held-out test set using:

- accuracy;
- sensitivity;
- specificity;
- balanced accuracy;
- Cohen's kappa;
- confusion matrices; and
- receiver operating characteristic curves and area under the curve (ROC-AUC).

## Results

Random Forest achieved the strongest held-out test performance.

| Model | Accuracy | Sensitivity | Specificity | ROC-AUC | Kappa |
| --- | ---: | ---: | ---: | ---: | ---: |
| LASSO logistic regression | 80.43% | 81.09% | 79.77% | 0.87 | 0.6086 |
| Bagging trees | 87.78% | 89.81% | 85.79% | 0.91 | 0.7557 |
| Random Forest | **92.65%** | **92.37%** | **92.92%** | **0.95** | **0.8529** |

These results relate to this academic dataset and experimental setup. They should not be interpreted as evidence of operational performance in a live network environment.

## Technologies used

- R
- RStudio (optional development environment)
- `tidyverse`
- `caret`
- `glmnet`
- `ipred`
- `rpart`
- `ranger`
- `forcats`
- `pROC`
- `doParallel` and `foreach`

## Instructions for running the R code

1. Clone or download this repository and open its root directory in R or RStudio.

2. Install the required packages if they are not already installed:

   ```r
   install.packages(c(
     "tidyverse", "caret", "glmnet", "ipred", "rpart", "ranger",
     "forcats", "pROC", "doParallel", "foreach"
   ))
   ```

3. Create a local `data` directory and place the authorised dataset inside it as:

   ```text
   data/WACY-COM.csv
   ```

4. Set a private integer seed for reproducibility. Do not use a student ID or other personal identifier:

   ```r
   Sys.setenv(WACY_SEED = "12345")
   ```

5. Run the analysis from the repository root:

   ```r
   source("network_intrusion_detection.R")
   ```

The script creates `figures/` and `results/` automatically. Model tuning can be computationally intensive because the bagging and Random Forest searches evaluate multiple parameter combinations in parallel.

## Repository structure

```text
network-intrusion-detection-r/
├── README.md
├── network_intrusion_detection.R
├── .gitignore
├── data/
│   └── WACY-COM.csv                 # Local only; not committed
├── figures/
│   ├── lasso_cv_auc.png
│   ├── bagging_oob_error.png
│   ├── random_forest_oob_error.png
│   └── model_roc_curves.png
└── results/
    ├── model_performance_summary.csv
    ├── test_confusion_counts.csv
    └── session_info.txt
```

The `figures/` and `results/` directories are generated when the analysis runs. The `data/` directory should remain excluded from version control.


