# Threshold Values Selection
Since semantic features CS, AS, and FS can not always be captured, we concatenate them to calculate a score as a part I of overall similarity.
The semantic feature MS is abundant in target functions so it is calculated as another part (i.e. part II) of similarity.


We collect these features by executing target functions with given PoC.
Then we calculate scores within different part scores between target functions and functions in vulnerability signature.
After getting these part scores, we need to assign weights to different part scores to calculate an overall similarity.
Instead manually assignment, we utilize Support Vector Machines (SVM) to calculate the better fit-weights.
Specifically, we extract the labels for target funtions from our ground truth for OpenSSL (i.e. 1 for patched function and -1 for vulnerable function).
Then we calculate the weights for two part scores to get the best overall detection (classification) accuracy based on SVM.
Then we record the weights and assign them to different parts of scores to complete the whole similarity equation.
