# WACY-COM intrusion-detection analysis
# Required packages (install once if needed):
# tidyverse, caret, glmnet, ipred, rpart, ranger, forcats, pROC, doParallel

library(tidyverse)
library(caret)
library(glmnet)
library(ipred)
library(rpart)
library(ranger)
library(forcats)
library(pROC)
library(doParallel)

dir.create("results", showWarnings = FALSE, recursive = TRUE)
dir.create("figures", showWarnings = FALSE, recursive = TRUE)

# Keep the original analysis seed private when publishing the repository.
# Before running, set it locally, for example: Sys.setenv(WACY_SEED = "your_integer_seed")
seed_text <- Sys.getenv("WACY_SEED", unset = "")
if (!nzchar(seed_text) || is.na(suppressWarnings(as.integer(seed_text)))) {
  stop("Set WACY_SEED to an integer before running this analysis.")
}
analysis_seed <- as.integer(seed_text)

# Import the dataset. Store it locally under data/; do not publish it unless permitted.
data_path <- file.path("data", "WACY-COM.csv")
if (!file.exists(data_path)) {
  stop("Dataset not found at data/WACY-COM.csv")
}
dat <- read.csv(data_path, na.strings = NA, stringsAsFactors = TRUE)
str(dat)

WACY_COM_cleaned <- dat %>%
  
  # Step 1: Removing outlier rows
  filter(Average.ping.to.attacking.IP.milliseconds != 99999,
         Attack.Source.IP.Address.Count >= 0) %>%
  
  # Step 2: Removing the problematic column before NA filtering
  select(-IP.Range.Trust.Score,
         -Source.Port.Range) %>%
  mutate(Source.OS.Detected = na_if(Source.OS.Detected, "???" )) %>%
  
  mutate(Average.ping.variability = log(Average.ping.variability)) %>%
  
  # ii) collapse OS categories
  mutate(Source.OS.Detected = fct_collapse(Source.OS.Detected,
                                      Windows_All = c("Windows 10", "Windows Server 2008")
    ),
    Target.Honeypot.Server.OS = fct_collapse(Target.Honeypot.Server.OS,
                                             Windows_DeskServ = c("Windows (Desktops)", "Windows (Servers)"),
                                             MacOS_Linux    = c("Linux", "MacOS (All)")
    )
  ) %>%
  # iii) ping/URL/IP/count transforms
  mutate(
    `log_AvgPingVar`           = log(`Average.ping.variability`),
    `Hits_sqrt`                = sqrt(`Hits`),
    `AttackSrcIP_Count_sqrt`   = sqrt(`Attack.Source.IP.Address.Count`),
    `AvgPingToAttackIP_sqrt`   = sqrt(`Average.ping.to.attacking.IP.milliseconds`),
    `URLs_requested_sqrt`      = sqrt(`Individual.URLs.requested`)
  ) %>%
  select(
    -`Average.ping.variability`,    # drop originals once transformed
    -`Hits`,
    -`Attack.Source.IP.Address.Count`,
    -`Average.ping.to.attacking.IP.milliseconds`,
    -`Individual.URLs.requested`
  ) %>%
  # iv) keep only complete cases
  na.omit()

# quick check
View(WACY_COM_cleaned)

set.seed(analysis_seed)
n_total <- nrow(WACY_COM_cleaned)

#splitting 30% for training dataset

train <- sample(
  x      = seq_len(n_total),
  size   = floor(0.30 * n_total)
)
# 1. Subset into train and test sets
train_set <- WACY_COM_cleaned[ train, ]
test_set  <- WACY_COM_cleaned[-train, ]


# 2. Checking dimensions
nrow(train_set)  # should be floor(0.30 * n_total)
nrow(test_set)   # should be n_total - nrow(train_set)

# 3. Save only the row counts/metrics by default; avoid publishing derived raw records.

# 4. quick sanity checks
cat("Training rows:", nrow(train_set), "\n")
cat(" Test rows:  ", nrow(test_set),     "\n")

# determing the three ML models
set.seed(analysis_seed)
models.list1 <- c("Logistic Ridge Regression",
                  "Logistic LASSO Regression",
                  "Logistic Elastic-Net Regression")
models.list2 <- c("Classification Tree",
                  "Bagging Tree",
                  "Random Forest")
myModels <- c(sample(models.list1,size=1),
              sample(models.list2,size=2))
myModels %>% data.frame

# Ensure APT is factor "No"/"Yes"
train_set$APT <- factor(train_set$APT, levels = c("No","Yes"))
test_set$APT  <- factor(test_set$APT,  levels = c("No","Yes"))
# Prepare parallel backend.
cl <- makePSOCKcluster(max(1, parallel::detectCores() - 1))
registerDoParallel(cl)

# Common CV control for LASSO
ctrl_l <- trainControl(
  method         = "cv",
  number         = 5,             
  classProbs     = TRUE,
  summaryFunction= twoClassSummary,
  allowParallel  = TRUE
)

# LASSO (5-fold CV, 20 λ)
set.seed(analysis_seed)
mod_lasso <- train(
  APT ~ ., data       = train_set,
  method     = "glmnet",
  preProcess = c("center","scale"),
  tuneGrid   = expand.grid(
    alpha  = 1,
    lambda = 10^seq(-4, 1, length = 20)
  ),
  metric    = "ROC",
  trControl = ctrl_l
)
mod_lasso$bestTune$lambda
# Finding the exact row 
best_lambda <- mod_lasso$bestTune$lambda
names(mod_lasso$results)
# Retrieve the CV-averaged metrics. With twoClassSummary these columns are
# ROC, sensitivity and specificity (not accuracy and kappa).
tuning_row <- mod_lasso$results[ mod_lasso$results$lambda == best_lambda, ]
tuning_row %>%
  select(lambda, ROC, ROCSD, Sens, SensSD, Spec, SpecSD) %>%
  print()
  
# Save the LASSO tuning plot.
png("figures/lasso_cv_auc.png", width = 1000, height = 750, res = 140)
print(plot(mod_lasso))
dev.off()
lasso_preds <- predict(mod_lasso, newdata = test_set)

# Confusion matrix 
conf_lasso <- confusionMatrix(
  data = lasso_preds,
  reference = test_set$APT,
  positive = "Yes"
)
print(conf_lasso)
print(mod_lasso)      # summary of tuning results for LASSO

# 2) Parallel OOB grid‐search for Bagging
grid_bag <- expand.grid(
  nbagg    = c(25, 50, 100),
  cp       = c(0.01, 0.05, 0.10),
  minsplit = c(10, 20, 30)
)

# compute OOB error in parallel
oob_err <- foreach(i = 1:nrow(grid_bag), .combine = c, 
                   .packages = c("ipred","rpart")) %dopar% {
                     b <- ipred::bagging(
                       APT ~ ., data    = train_set,
                       nbagg   = grid_bag$nbagg[i],
                       control = rpart.control(
                         cp       = grid_bag$cp[i],
                         minsplit = grid_bag$minsplit[i]
                       ),
                       coob    = TRUE
                     )
                     b$err * 100
                   }
grid_bag$OOB_err <- oob_err
best_bag <- grid_bag[which.min(grid_bag$OOB_err), ]
best_bag # optimal bagging
# fit final bagged model
final_bag <- ipred::bagging(
  APT ~ ., data    = train_set,
  nbagg   = best_bag$nbagg,
  control = rpart.control(
    cp       = best_bag$cp,
    minsplit = best_bag$minsplit
  ),
  coob    = TRUE
)
final_bag$err * 100
best_cp   <- best_bag$cp
best_ms   <- best_bag$minsplit

df_bag    <- grid_bag %>% filter(cp == best_cp, minsplit == best_ms)

# Plot and save the bagging OOB error.
bag_oob_plot <- ggplot(df_bag, aes(x = nbagg, y = OOB_err)) +
  geom_line() + geom_point() +
  labs(
    title = sprintf("Bagging OOB Error (cp=%.2f, minsplit=%d)", best_cp, best_ms),
    x = "Number of Trees (nbagg)",
    y = "OOB Misclassification Rate (%)"
  ) +
  theme_minimal()
print(bag_oob_plot)
ggsave("figures/bagging_oob_error.png", bag_oob_plot, width = 7, height = 5, dpi = 160)

# confusion matrix of Bagging 
bag_preds <- predict(final_bag, newdata = test_set, type = "class")
conf_bag <- confusionMatrix(
  data = bag_preds,
  reference = test_set$APT,
  positive = "Yes"
)
print(conf_bag)

# 3) Parallel OOB grid‐search for Random Forest
p  <- ncol(train_set) - 1
m0 <- floor(sqrt(p))
grid_rf <- expand.grid(
  num.trees       = c(200, 500, 1000),
  mtry            = c(m0-1, m0, m0+1),
  min.node.size   = c(1, 5, 10),
  replace         = c(TRUE, FALSE),
  sample.fraction = c(0.6, 0.8, 1.0)
)

oob_rf <- foreach(i = 1:nrow(grid_rf), .combine = c, 
                  .packages = "ranger") %dopar% {
                    rf <- ranger(
                      APT ~ ., data            = train_set,
                      num.trees        = grid_rf$num.trees[i],
                      mtry             = grid_rf$mtry[i],
                      min.node.size    = grid_rf$min.node.size[i],
                      replace          = grid_rf$replace[i],
                      sample.fraction  = grid_rf$sample.fraction[i],
                      probability      = TRUE,
                      respect.unordered.factors = "order",
                      seed             = analysis_seed
                    )
                    rf$prediction.error * 100
                  }
grid_rf$OOB_err <- oob_rf
best_rf <- grid_rf[which.min(grid_rf$OOB_err), ]
best_rf              # optimal RF 
# fit final RF
final_rf <- ranger(
  APT ~ ., data            = train_set,
  num.trees        = best_rf$num.trees,
  mtry             = best_rf$mtry,
  min.node.size    = best_rf$min.node.size,
  replace          = best_rf$replace,
  sample.fraction  = best_rf$sample.fraction,
  probability      = TRUE,
  respect.unordered.factors = "order",
  seed             = analysis_seed
)

# Plot and save the Random Forest OOB error.
best_nt   <- best_rf$num.trees
best_mns  <- best_rf$min.node.size
best_rf_frac <- best_rf$sample.fraction
df_rf     <- grid_rf %>%
  filter(num.trees == best_nt,
         min.node.size == best_mns,
         sample.fraction == best_rf_frac)
rf_oob_plot <- ggplot(df_rf, aes(x = mtry, y = OOB_err)) +
  geom_line() + geom_point() +
  labs(
    title = sprintf("RF OOB Error (trees=%d, nodeSize=%d, frac=%.1f)",
                    best_nt, best_mns, best_rf_frac),
    x = "Features Tried at Each Split (mtry)",
    y = "OOB Misclassification Rate (%)"
  ) +
  theme_minimal()
print(rf_oob_plot)
ggsave("figures/random_forest_oob_error.png", rf_oob_plot, width = 7, height = 5, dpi = 160)

rf_raw <- predict(final_rf, data = test_set)$predictions  
# rf_raw is an n × 2 matrix; (“No”, “Yes”)

# Converting to hard class (threshold at 0.5)
rf_class <- factor(
  ifelse(rf_raw[, "Yes"] > 0.5, "Yes", "No"),
  levels = c("No","Yes")
)
# Confusion matrix for Random Forest
conf_rf <- confusionMatrix(
  data = rf_class,
  reference = test_set$APT,
  positive = "Yes"
)
print(conf_rf)

# 4) Shutdown parallel backend
stopCluster(cl)
registerDoSEQ()

# 1. Computing ROC objects 
roc_lasso <- roc(test_set$APT,
                 predict(mod_lasso, test_set, type="prob")[, "Yes"],
                 levels = c("No","Yes"), direction="<")

roc_rf    <- roc(test_set$APT,
                 rf_raw[,"Yes"],
                 levels = c("No","Yes"), direction="<")

roc_bag   <- roc(test_set$APT,
                 predict(final_bag, newdata = test_set, type="prob")[, "Yes"],
                 levels = c("No","Yes"), direction="<")

# 2. Plotting and saving the ROC curves.
png("figures/model_roc_curves.png", width = 1000, height = 750, res = 140)
plot(roc_lasso,
     col  = "blue",
     lwd  = 2,
     main = "ROC Curves: LASSO, RF & Bagging")

# 3. Adding the other curves 
lines(roc_rf,  col = "darkgreen", lwd = 2)
lines(roc_bag, col = "red",      lwd = 2)

# 4. Adding a legend
legend("bottomright",
       legend = c("LASSO","Random Forest","Bagging"),
       col    = c("blue","darkgreen","red"),
       lwd    = 2)
dev.off()

# Build one authoritative performance table directly from the test-set
# confusion matrices and ROC objects. This prevents manual transcription errors.
extract_metrics <- function(model_name, cm, roc_object) {
  tibble(
    Model = model_name,
    Accuracy = unname(cm$overall["Accuracy"]),
    Sensitivity = unname(cm$byClass["Sensitivity"]),
    Specificity = unname(cm$byClass["Specificity"]),
    Balanced_Accuracy = unname(cm$byClass["Balanced Accuracy"]),
    AUC = as.numeric(pROC::auc(roc_object)),
    Kappa = unname(cm$overall["Kappa"])
  )
}

performance_summary <- bind_rows(
  extract_metrics("LASSO", conf_lasso, roc_lasso),
  extract_metrics("Bagging Trees", conf_bag, roc_bag),
  extract_metrics("Random Forest", conf_rf, roc_rf)
)

print(performance_summary)
write_csv(performance_summary, "results/model_performance_summary.csv")

# caret confusion matrices use prediction rows and reference/actual columns.
confusion_counts <- bind_rows(
  as.data.frame(conf_lasso$table) %>% mutate(Model = "LASSO", .before = 1),
  as.data.frame(conf_bag$table) %>% mutate(Model = "Bagging Trees", .before = 1),
  as.data.frame(conf_rf$table) %>% mutate(Model = "Random Forest", .before = 1)
)
write_csv(confusion_counts, "results/test_confusion_counts.csv")
writeLines(capture.output(sessionInfo()), "results/session_info.txt")

print(best_bag)      
print(best_rf)       
