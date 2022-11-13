```
** //////////////////////////////////////////// **
** ===========================================  **
** = Play Store Security Evaluation Analysis =  **
** ===========================================  **
** \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\  **
```

This dataset is part of a paper that discusses the evolution of app security within the Google Play Store between 2010 and 2021.
Legal disclaimer: The data is provided as-is for non-commercial research, without any warranty for completeness or correctness.

Dependencies
=============

We provide statistical data computed from VUSC results. This data is useable without a VUSC installation. To re-run the original
analysis, or to re-run the data extraction from the code scanner, you need a VUSC server. Contact the folks at CyWare
(https://secure-software.io/) for an academic license.

To obtain our original apps, you can query AndroZoo with the SHA256 hashes of the apps in the "AppsToAnalyze" table (see below).

Folders
========

This dataset consists of three folders:

1. VulnerabilityAnalysis
    This folder contains the statistical data obtained from the VUSC output with all security analyses enabled. The crypto analyses
    were run against the default knowledgebase configuration (e.g., default settings as to which algorithms to consider insecure).
2. CryptoAnalysis
    The statistical data in this folder was derived from a VUSC run in which all crypto algorithms were considered insecure. Only
    the crypto checks were enabled as analyses. With this configuration, VUSC creates a vulnerability marker for each code location
    that uses cryptography. In the paper, we se this dataset to determine how often cryptography is used in general and to calculate
    the percentage of outdated crypto over all crypto. We further use these reports to quantify the use of non-outdated crypto
    algorithms such as AES.
3. Code
    This folder contains all the source code for the analysis. It has two subfolders:
    a) AppsPerYearAnonymizer
        This folder contains the tool that was used to anonymize the dataset. See the description of the dataset below for why we had
        to anonymize and how we did it.
    b) StatisticsAnalyzer
        This folder contains the code of the statistical analysis program that we use to submit jobs to the VUSC server, analyze the
        vulnerability findings, and create the contents of the statistics tables. The output of this program can be found in the two
        data folders (VulnerabilityAnalysis and CryptoAnalysis).

Tables
=======

Each dataset folder (VulnerabilityAnalysis and CryptoAnalysis) consists of the same set of tables:

* AppsToAnalyze (see footnote (*))
    This table contains one row per app in our dataset. It links each app (identified by its sha256 hash) to the respective file on
    disk and the corresponding VUSC job ID. Note that the two VUSC runs (VulnerabilityAnalysis and CryptoAnalysis) are independent
    and therefore have different job IDs for the same app. To link an app between the runs, use the sha256 hash. Further, this table
    contains the size of each app (number of classes, methods, units) as well as the number of library classes.

* LibraryCategoryFindingCount
    This table records the number of findings in a particular library over all jobs, per finding category.

* LibraryCryptoCount
    This table contains the cryptographic algorithms that are used inside libraries.

* LibraryFindingCount
    This table contains the vulnerabilities discovered in libraries.

* NumCryptoUses
    This table contains the number of times a crypto finding has been found per app, identified by its sha256 hash.

* OutdatedAlgorithmStatistics
    This table contains the crypto algorithms used in the different apps and the percentage of how many findings stem from libraries.

* PerCategoryFindingCount
    This table conains how many vulnerabilities of which category in which app. It presents the link between vulnerability and the
    category to which it belongs.

* VulnerabilitiesPerCategory
    This table contains counts how many vulnerabilities have been detected for which category in which app. It focuses only on
    categories and does not contain the individual vulnerabilities.

* VulnerabilityCounts
    This table contains the counts for each vulnerability and each app in the dataset.

(*) Due to the large number of findings (more than 500,000 results across 3,600 apps), we were unable to perform a proper responsible
disclosure process. This would have required manual post-processing of all findings, identifying contacts with the developers of each
affected, app, etc. We instead chose to randomize the Job ID in the dataset. For each job, we randomly selected one of the IDs from
all 300 apps of the same year. This approach keeps the mapping between year and findings intact (which is at the core of this paper),
but avoids disclosing individual vulnerabilities.

Raw VUSC Results
=================

We have performed two runs using the VUSC scanner, VulnerabilityAnalysis and CryptoAnalysis as explained above. VUSC stores its
raw analysis results in one PostgreSQL database per run. The database dump for one run is larger than 19 GB as a compressed
tar.gz file. The entire study is therefore roughly 40 GB. We are happy to provide these dumps on request using our private
file hosting system. Please contact the paper authors for details.

Analysis Program
=================

The analysis program is used to submit jobs to a VUSC server and to perform statistical analysis on the VUSC results. We provide a
JAR with dependencies to make running the program easier. It supports the following parameters:

java -Xmx25g -jar AnalysisExecutor.jar [OPTIONS]

    -d      Database URL, e.g., jdbc:postgresql://localhost/vusc-appsperyear
    -u      Database username

    -w      Database password
    -v  	VUSC Server URL
    -a      Text file with APK files to analyze, one per line
    -y      The year to which the apps taken from "-a" belong
    -j      Android JAR directory, e.g., /opt/android-sdk-linux/platforms

    -s      Submit the jobs from the app file to the VUSC server
    -r      Retrieve package name and version from the VUSC results
    -i      Analyze the app sizes
    -c1     Analyze the vulnerabilities per category
    -c2     Analyze the vulnerabilities per category
    -t1     Unused.
    -t2     Analyze the crypto statistics
    -cl     Analyze the distribution between app and library code

The VUSC SDK is available via Maven Central. However, we re-use some internal VUSC modules for efficiently dealing with scan
results, computing statistics, etc. This is not an issue if you have a VUSC academic license, which grants you access to a
full Maven repository with the scanner modules. Before compiling, you need to provide the URL of your VUSC Maven repository
in the POM file.

Frequently Asked Questions (FAQ)
=================================

* Why is there a year 20162?

As stated in the paper, we found outliers in the 2016 dataset from AndroZoo and therefore ran the anaylsis again on another
dataset from the same year, this time from dlapk.

* Why is the number of records different in table "AppsToAnalyze" between VulnerabilityAnalysis and CryptoAnalysis?

Since we found that the 2016 outlier exists in both datasets, we concluded that both datasets are equally representative
for 2016. We therefore did not re-run the crypto analysis on the secondary dataset for 2016. This leads to 300 records
less. Further, depending on the VUSC configuration, some apps may yield results or not, or may fail during analysis or
not. This introduces an additional variation.
