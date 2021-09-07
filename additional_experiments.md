# Table 1. Accuracy Across Optimizations  (O2 signature)
|Tool\Optimization| O0 | O1 | O2| O3 |
|-|-|-|-|-|
|BinXray|84%|34%|31%|16%|
|Robin(our tool)|88%|85%|82%|74%|

We conduct the patch detection with signatures generated with optimization level O2.

The first row denotes the optimization levels adopted when compiling the detected target software.


# Table 2. False Positive(FP) Rate of Different Tools
|Tool| FP@Top-10 | FP@Top-5 | FP@Top-1|
|-|-|-|-|
|SAFE|82%|80%|66%|
|Gemini|72%|69%|33%|

The table shows the false postive rates in the function matching results.

A false positive refers to a patched function being mistaken for a vulnerable function.
