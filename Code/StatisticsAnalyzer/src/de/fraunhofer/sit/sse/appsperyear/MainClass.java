package de.fraunhofer.sit.sse.appsperyear;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.math3.linear.OpenMapRealMatrix;
import org.apache.commons.math3.stat.correlation.SpearmansCorrelation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.spi.LoggerContext;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import de.codeinspect.collections.CountingMap;
import de.codeinspect.collections.tables.CountingTable;
import de.codeinspect.math.functions.LinearFunction;
import de.codeinspect.math.regression.CorrelationAnalysis;
import de.codeinspect.math.regression.RegressionResult;
import de.fraunhofer.sit.sse.appsperyear.database.AppToAnalyze;
import de.fraunhofer.sit.sse.appsperyear.database.CryptoStatistics;
import de.fraunhofer.sit.sse.appsperyear.database.DatabaseManager;
import de.fraunhofer.sit.sse.appsperyear.database.LibraryCategoryFindingCount;
import de.fraunhofer.sit.sse.appsperyear.database.LibraryCryptoCount;
import de.fraunhofer.sit.sse.appsperyear.database.LibraryFindingCount;
import de.fraunhofer.sit.sse.appsperyear.database.OutdatedAlgorithmStatistics;
import de.fraunhofer.sit.sse.appsperyear.database.PerCategoryFindingCount;
import de.fraunhofer.sit.sse.appsperyear.database.VulnerabilitiesPerCategory;
import de.fraunhofer.sit.sse.appsperyear.database.VulnerabilityCounts;
import de.fraunhofer.sit.sse.vusc.javaclient.api.JobsApi;
import de.fraunhofer.sit.sse.vusc.javaclient.api.KnowledgebaseApi;
import de.fraunhofer.sit.sse.vusc.javaclient.invoker.ApiClient;
import de.fraunhofer.sit.sse.vusc.javaclient.invoker.ApiException;
import de.fraunhofer.sit.sse.vusc.javaclient.models.APKMetadata;
import de.fraunhofer.sit.sse.vusc.javaclient.models.AdditionalData;
import de.fraunhofer.sit.sse.vusc.javaclient.models.CodeLocation;
import de.fraunhofer.sit.sse.vusc.javaclient.models.DetailedJobStatus;
import de.fraunhofer.sit.sse.vusc.javaclient.models.InformationFinding;
import de.fraunhofer.sit.sse.vusc.javaclient.models.Job;
import de.fraunhofer.sit.sse.vusc.javaclient.models.JobMetadata;
import de.fraunhofer.sit.sse.vusc.javaclient.models.JobResults;
import de.fraunhofer.sit.sse.vusc.javaclient.models.UsedLibrary;
import de.fraunhofer.sit.sse.vusc.javaclient.models.VulnerabilityFinding;
import soot.G;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;

/**
 * The main class for the command-line utility for the analysis of app
 * vulnerabilities per year
 * 
 * @author Steven Arzt
 *
 */
public class MainClass {

	private static final int READ_TIMEOUT = 180_000;
	private static final int CONNECT_TIMEOUT = 120_000;

	private static final String OPTION_DB_URL = "d";
	private static final String OPTION_DB_USER = "u";
	private static final String OPTION_DB_PWD = "w";

	private static final String OPTION_VUSC_URL = "v";
	private static final String OPTION_APP_FILES = "a";
	private static final String OPTION_YEAR = "y";
	private static final String OPTION_ANDROID_JARS = "j";

	private static final String OPTION_SUBMIT = "s";
	private static final String OPTION_ANALYZE_RESULTS = "r";
	private static final String OPTION_ANALYZE_SIZES = "i";
	private static final String OPTION_ANALYZE_VULNS_PER_CATEGORY1 = "c1";
	private static final String OPTION_ANALYZE_VULNS_PER_CATEGORY2 = "c2";
	private static final String OPTION_ANALYZE_CRYPTO_STATS1 = "t1";
	private static final String OPTION_ANALYZE_CRYPTO_STATS2 = "t2";
	private static final String OPTION_ANALYZE_CODE_APP_LIB = "cl";

	private static final String OPTION_PERFORM_REGRESSION = "e";

	private static Logger logger;

	protected static final Options options = new Options();

	static {
		initializeCommandLineOptions();
	}

	/**
	 * Initializes the set of available command-line options
	 */
	private static void initializeCommandLineOptions() {
		options.addOption(OPTION_DB_URL, "dburl", true, "The JDBC url for connecting to the database");
		options.addOption(OPTION_DB_USER, "dbuser", true, "The user for accessing the database");
		options.addOption(OPTION_DB_PWD, "dbpwd", true, "The password for accessing the database");

		options.addOption(OPTION_VUSC_URL, "vuscurl", true, "The URL for accessing the VUSC scanner");
		options.addOption(OPTION_APP_FILES, "appfiles", true, "File with paths to the individual APKs");
		options.addOption(OPTION_YEAR, "year", true, "The year in which the APKs were released");
		options.addOption(OPTION_ANDROID_JARS, "androidjars", true, "Directory with the Android platform JARs");

		options.addOption(OPTION_SUBMIT, "submit", false, "Submit the analysis jobs to the VUSC server");
		options.addOption(OPTION_ANALYZE_RESULTS, "findjobs", false, "Analyze the job results for statistics");
		options.addOption(OPTION_ANALYZE_SIZES, "analyzesizes", false, "Analyze the app sizes for statistics");
		options.addOption(OPTION_ANALYZE_VULNS_PER_CATEGORY1, "vulnspercat1", false,
				"Analyze the number of vulnerabilities per category");
		options.addOption(OPTION_ANALYZE_VULNS_PER_CATEGORY2, "vulnspercat2", false,
				"Count the number of vulnerabilities and categories");
		options.addOption(OPTION_ANALYZE_CRYPTO_STATS1, "cryptostat1", false,
				"Analyze the crypto statistics (number of crypto API uses)");
		options.addOption(OPTION_ANALYZE_CRYPTO_STATS2, "cryptostat2", false,
				"Analyze the reported outdated crypto algorithms");
		options.addOption(OPTION_ANALYZE_CODE_APP_LIB, "applibstats", false,
				"Analyze the fraction of the overall code that comes from libraries");

		options.addOption(OPTION_PERFORM_REGRESSION, "regression", true, "Perform regression analysis on the data");
	}

	public static void main(String[] args) {
		// Explicitly load log configuration
		File logConfigFile = new File("log4j2.properties");
		if (logConfigFile.exists()) {
			System.out.println(String.format("Loading log configuration from %s", logConfigFile.getAbsolutePath()));
			LoggerContext context = Configurator.initialize(null, logConfigFile.toURI().toString());
			if (context == null)
				System.err.println("Could not load log configuration file");
			else
				logger = context.getLogger(MainClass.class);
		}
		if (logger == null)
			logger = LogManager.getLogger(MainClass.class);

		// We need proper parameters
		final HelpFormatter formatter = new HelpFormatter();
		if (args.length == 0) {
			formatter.printHelp("java -jar AnalysisExtractor.jar [OPTIONS]", options);
			return;
		}

		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse(options, args);

			// Get the database details
			String dbUrl = cmd.getOptionValue(OPTION_DB_URL);
			String dbUser = cmd.getOptionValue(OPTION_DB_USER);
			String dbPwd = cmd.getOptionValue(OPTION_DB_PWD);
			if (dbUrl == null || dbUrl.isEmpty() || dbUser == null || dbUser.isEmpty() || dbPwd == null
					|| dbPwd.isEmpty()) {
				logger.error("Database url, user, or password not specified");
				return;
			}
			DatabaseManager dbManager = new DatabaseManager(dbUrl, dbUser, dbPwd);

			// Compute the metadata for the new app list
			String appFiles = cmd.getOptionValue(OPTION_APP_FILES);
			String year = cmd.getOptionValue(OPTION_YEAR);
			if (appFiles != null && !appFiles.isEmpty() && year != null && !year.isEmpty())
				computeAppMetadata(appFiles, Integer.valueOf(year), dbManager);

			// Collect statistics about the app sizes
			if (cmd.hasOption(OPTION_ANALYZE_SIZES)) {
				String androidJars = cmd.getOptionValue(OPTION_ANDROID_JARS);
				if (androidJars == null || androidJars.isEmpty()) {
					System.err.println("No Android platform JAR directory specified");
					return;
				}
				analyzeAppSizes(dbManager, androidJars);
				return;
			}

			String vuscURL = cmd.getOptionValue(OPTION_VUSC_URL);
			if (vuscURL == null || vuscURL.isEmpty()) {
				System.err.println("No VUSC server URL specified");
				return;
			}

			// Submit the analysis jobs
			if (cmd.hasOption(OPTION_SUBMIT))
				submitJobs(appFiles, vuscURL);

			// Analyze the job results
			if (cmd.hasOption(OPTION_ANALYZE_RESULTS))
				analyzeJobs(vuscURL, dbManager);

			// Compute the number of vulnerabilities per category
			if (cmd.hasOption(OPTION_ANALYZE_VULNS_PER_CATEGORY1))
				analyzeVulnerabilitiesPerCategory1(vuscURL, dbManager);
			if (cmd.hasOption(OPTION_ANALYZE_VULNS_PER_CATEGORY2))
				analyzeVulnerabilitiesPerCategory2(vuscURL, dbManager);

			// Analyze the crypto statistics
			if (cmd.hasOption(OPTION_ANALYZE_CRYPTO_STATS1))
				analyzeCryptoStats1(vuscURL, dbManager);
			if (cmd.hasOption(OPTION_ANALYZE_CRYPTO_STATS2))
				analyzeCryptoStats2(vuscURL, dbManager);

			// Perform linear regression analysis for the vulnerability counts per year
			if (cmd.hasOption(OPTION_PERFORM_REGRESSION)) {
				String inputFile = cmd.getOptionValue(OPTION_PERFORM_REGRESSION);
				if (inputFile == null || inputFile.isBlank()) {
					System.err.println("No data file specified");
					return;
				}
				performRegressionAnalysis(dbManager, inputFile);
			}

			// Check which fraction of the codes is from a library
			if (cmd.hasOption(OPTION_ANALYZE_CODE_APP_LIB)) {
				String androidJars = cmd.getOptionValue(OPTION_ANDROID_JARS);
				if (androidJars == null || androidJars.isEmpty()) {
					System.err.println("No Android platform JAR directory specified");
					return;
				}
				analyzeLibraryAppCodeRatio(androidJars, vuscURL, dbManager);
			}
		} catch (ParseException ex) {
			formatter.printHelp("java -jar CorrelationAnalysis.jar [OPTIONS]", options);
			return;
		} catch (IOException e) {
			logger.error("IO error during correlation analysis", e);
		} catch (SQLException e) {
			logger.error("SQL error on backend database for correlations", e);
		}
	}

	/**
	 * Analyzes the ratio between library code and app-specific code in an app
	 * 
	 * @param androidJars The Android platform JARs
	 * @param vuscURL     The URL of the VUSC server on which to perform the
	 *                    statistical analysis
	 * @param dbManager   The manager class for interacting with the database
	 * @throws IOException
	 * @throws SQLException
	 */
	private static void analyzeLibraryAppCodeRatio(String androidJars, String vuscURL, DatabaseManager dbManager)
			throws IOException, SQLException {
		ApiClient client = new ApiClient();
		client.setBasePath(vuscURL);
		KnowledgebaseApi knowledgebase = new KnowledgebaseApi(client);

		LoadingCache<String, Boolean> libResults = CacheBuilder.newBuilder().build(new CacheLoader<String, Boolean>() {

			@Override
			public Boolean load(String key) throws Exception {
				List<UsedLibrary> libs = knowledgebase.getLibrariesByClassName(key);
				return libs != null && !libs.isEmpty();
			}

		});

		for (AppToAnalyze app : dbManager.getAllApps()) {
			try {
				// Don't analyze the same app twice
				if (app.numLibClasses > 0)
					continue;

				// Load the Soot instance
				G.reset();
				soot.options.Options options = soot.options.Options.v();
				options.set_process_dir(Collections.singletonList(app.apkFileName));
				options.set_src_prec(soot.options.Options.src_prec_apk);
				options.set_allow_phantom_refs(true);
				options.set_output_format(soot.options.Options.output_format_none);
				options.set_android_jars(androidJars);

				Scene scene = Scene.v();
				scene.loadNecessaryClasses();

				// Analyze the app size
				app.numLibClasses = 0;
				for (SootClass sc : scene.getApplicationClasses()) {
					String packageName = sc.getName();
					// The default package is always app-specific
					if (packageName.contains(".")) {
						packageName = packageName.substring(0, packageName.lastIndexOf("."));
						if (libResults.get(packageName))
							app.numLibClasses++;
						else
							app.numAppClasses++;
					} else
						app.numAppClasses++;
				}

				// Save the updated statistics
				dbManager.update(app);
			} catch (Exception ex) {
				logger.error(String.format("App size analysis for %s failed", app.apkFileName), ex);
			}
		}
	}

	/**
	 * Performs regression tests on the aggregated vulnerability data
	 * 
	 * @param dbManager The manager class for interacting with the database
	 * @param inputFile The input file for the regression analysis
	 * @throws IOException
	 */
	private static void performRegressionAnalysis(DatabaseManager dbManager, String inputFile) throws IOException {
		try (FileReader rdr = new FileReader(inputFile)) {
			CSVParser parser = CSVFormat.TDF.parse(rdr);
			List<CSVRecord> records = parser.getRecords();
			double[] x = new double[records.size()];
			double[] y = new double[records.size()];
			for (int i = 0; i < x.length; i++) {
				CSVRecord record = records.get(i);
				x[i] = Double.parseDouble(record.get(0));
				y[i] = Double.parseDouble(record.get(1));
			}
			RegressionResult<LinearFunction> regRes = CorrelationAnalysis.calculateLinearRegression(x, y);
			System.out.println("Regression error: " + regRes.getQuality());
			System.out.println("Function: " + regRes.getFunction());

			OpenMapRealMatrix dataMatrix = new OpenMapRealMatrix(x.length, 2);
			SpearmansCorrelation sc = new SpearmansCorrelation(dataMatrix);
			System.out.println("Correlation: " + sc.correlation(x, y));
		}
	}

	/**
	 * Collects statistics about the sizes of the apps in the dataset
	 * 
	 * @param dbManager   The manager class for interacting with the database
	 * @param androidJars The directory with the Android JARs
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void analyzeAppSizes(DatabaseManager dbManager, String androidJars)
			throws IOException, SQLException {
		for (AppToAnalyze app : dbManager.getAllApps()) {
			try {
				// Don't analyze the same app twice
				if (app.numClasses > 0 && app.numMethods > 0 && app.numUnits > 0)
					continue;

				// Load the Soot instance
				G.reset();
				soot.options.Options options = soot.options.Options.v();
				options.set_process_dir(Collections.singletonList(app.apkFileName));
				options.set_src_prec(soot.options.Options.src_prec_apk);
				options.set_allow_phantom_refs(true);
				options.set_output_format(soot.options.Options.output_format_none);
				options.set_android_jars(androidJars);

				Scene scene = Scene.v();
				scene.loadNecessaryClasses();

				// Analyze the app size
				app.numClasses = 0;
				app.numMethods = 0;
				app.numUnits = 0;
				for (SootClass sc : scene.getApplicationClasses()) {
					for (SootMethod sm : sc.getMethods()) {
						if (sm.isConcrete())
							app.numUnits += sm.retrieveActiveBody().getUnits().size();
						app.numMethods++;
					}
					app.numClasses++;
				}

				// Save the updated statistics
				dbManager.update(app);
			} catch (Exception ex) {
				logger.error(String.format("App size analysis for %s failed", app.apkFileName), ex);
			}
		}
	}

	/**
	 * Analyzes the jobs on the VUSC server for statistical data
	 * 
	 * @param vuscURL   The URL of the VUSC server on which to perform the
	 *                  statistical analysis
	 * @param dbManager The manager class for interacting with the database
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void analyzeJobs(String vuscURL, DatabaseManager dbManager) throws IOException, SQLException {
		ApiClient client = new ApiClient();
		client.setReadTimeout(READ_TIMEOUT);
		client.setConnectTimeout(CONNECT_TIMEOUT);
		client.setBasePath(vuscURL);
		JobsApi jobAPI = new JobsApi(client);
		try {
			// For performance reasons, we query the database first and then load the
			// respective job from the VUSC server
			int jobCount = 0;
			for (AppToAnalyze app : dbManager.getAppsWithoutMetadata()) {
				List<Job> jobs = jobAPI.getJobsByHash(app.sha256hash);
				if (jobs != null && !jobs.isEmpty()) {
					for (Job j : jobs) {
						// Skip failed jobs
						if (j.getIsFailed())
							continue;
						if (!j.getIsFinished())
							continue;

						// The job must be finished
						DetailedJobStatus status = j.getStatus();
						JobMetadata metadata = j.getMetadata();
						if (status != null && status.getFinishDate() != null && metadata != null) {
							app.jobId = j.getId();
							if (metadata instanceof APKMetadata) {
								APKMetadata apkMetadata = (APKMetadata) metadata;
								app.packageName = apkMetadata.getPackageName();
								app.versionName = apkMetadata.getVersionName();
							}
							dbManager.update(app);
							jobCount++;
						}

						// Do not look at multiple results for the same app
						break;
					}
				}
			}
			logger.info("Associated {} analysis jobs with their statistical record", jobCount);
		} catch (ApiException e) {
			logger.error(String.format("Could not obtain analysis jobs from %s", vuscURL), e);
		}
	}

	private static void doForEachJob(String vuscURL, DatabaseManager dbManager, IJobConsumer consumer)
			throws IOException, SQLException {
		ApiClient client = new ApiClient();
		client.setReadTimeout(READ_TIMEOUT);
		client.setConnectTimeout(CONNECT_TIMEOUT);
		client.setBasePath(vuscURL);
		JobsApi jobAPI = new JobsApi(client);
		KnowledgebaseApi knowledgebaseAPI = new KnowledgebaseApi(client);
		try {
			int jobCount = 0;
			for (AppToAnalyze app : dbManager.getAllApps()) {
				List<Job> jobs = jobAPI.getJobsByHash(app.sha256hash);
				if (jobs != null && !jobs.isEmpty()) {
					for (Job j : jobs) {
						// Skip all failed jobs
						if (j.getIsFailed())
							continue;
						if (!j.getIsFinished())
							continue;

						consumer.accept(j, knowledgebaseAPI);

						// Do not look at multiple results for the same app
						jobCount++;
						break;
					}
				}
			}
			logger.info("Collected the vulnerabilities of {} analysis jobs", jobCount);
		} catch (ApiException e) {
			logger.error(String.format("Could not obtain analysis jobs from %s", vuscURL), e);
		}
	}

	/**
	 * Analyzes the jobs on the VUSC server for statistical data
	 * 
	 * @param vuscURL   The URL of the VUSC server on which to perform the
	 *                  statistical analysis
	 * @param dbManager The manager class for interacting with the database
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void analyzeVulnerabilitiesPerCategory1(String vuscURL, DatabaseManager dbManager)
			throws IOException, SQLException {
		CountingTable<String, String> totalLibFindingsPerCategory = new CountingTable<>();
		CountingTable<String, String> totalLibFindingsPerType = new CountingTable<>();

		doForEachJob(vuscURL, dbManager, (j, kAPI) -> {
			try {
				JobResults results = j.getJobResults();
				if (results != null) {
					List<VulnerabilityFinding> vulnFindings = results.getVulnerabilityFindings();
					if (vulnFindings != null && !vulnFindings.isEmpty()) {
						CountingMap<String> findingsPerCategory = new CountingMap<>();
						CountingMap<String> findingsPerType = new CountingMap<>();
						CountingTable<String, String> libraryFindingsPerCategory = new CountingTable<>();
						CountingTable<String, String> libraryFindingsPerType = new CountingTable<>();

						// Count the vulnerabilities and categories
						for (VulnerabilityFinding finding : vulnFindings) {
							findingsPerCategory.increment(finding.getCategory());
							findingsPerType.increment(finding.getType());

							if (finding.getLocation() instanceof CodeLocation) {
								CodeLocation codeLoc = (CodeLocation) finding.getLocation();
								List<UsedLibrary> libInfo = kAPI.getLibrariesByClassName(codeLoc.getClassName());
								if (libInfo != null && !libInfo.isEmpty()) {
									String libName = libInfo.iterator().next().getName();
									libraryFindingsPerCategory.increment(finding.getCategory(), libName);
									libraryFindingsPerType.increment(finding.getType(), libName);
								}
							}
						}

						// Report the findings per category
						for (String cat : findingsPerCategory.keySet()) {
							Integer findings = findingsPerCategory.get(cat);
							Integer libFindings = libraryFindingsPerCategory.rowSum(cat);

							VulnerabilitiesPerCategory dbObject = new VulnerabilitiesPerCategory();
							dbObject.jobId = j.getId();
							dbObject.category = cat;
							dbObject.numVulnerabilities = findings;
							dbObject.numLibVulns = libFindings;
							if (findings != null && libFindings != null && findings != 0 && libFindings != 0)
								dbObject.libraryPercentage = ((float) libFindings) / (float) (findings + libFindings)
										* 100f;
							dbManager.addToDatabase(dbObject);
						}

						// Report the findings per type
						for (String type : findingsPerType.keySet()) {
							Integer findings = findingsPerType.get(type);
							Integer libFindings = libraryFindingsPerType.rowSum(type);

							VulnerabilityCounts dbObject = new VulnerabilityCounts();
							dbObject.jobId = j.getId();
							dbObject.vulnType = type;
							dbObject.numVulnerabilities = findings;
							dbObject.numLibVulns = libFindings;
							if (findings != null && libFindings != null && findings != 0 && libFindings != 0)
								dbObject.libraryPercentage = ((float) libFindings) / (float) (findings + libFindings)
										* 100f;
							dbManager.addToDatabase(dbObject);
						}

						totalLibFindingsPerType.addAll(libraryFindingsPerType);
						totalLibFindingsPerCategory.addAll(libraryFindingsPerCategory);
					}
				}
			} catch (SQLException | IOException | ApiException ex) {
				logger.error(String.format("Could not obtain analysis jobs from %s", vuscURL), ex);
			}
		});

		// Record how often the individual libraries are responsible for findings
		for (String libName : totalLibFindingsPerType.columnKeySet()) {
			for (String vuln : totalLibFindingsPerType.rowKeySet()) {
				LibraryFindingCount libCount = new LibraryFindingCount();
				libCount.libraryName = libName;
				libCount.vulnType = vuln;
				libCount.numFindings = totalLibFindingsPerType.get(vuln, libName);
				dbManager.addToDatabase(libCount);
			}
		}

		// Record how often the individual libraries are responsible for findings in
		// categories
		for (String libName : totalLibFindingsPerCategory.columnKeySet()) {
			for (String cat : totalLibFindingsPerCategory.rowKeySet()) {
				LibraryCategoryFindingCount libCount = new LibraryCategoryFindingCount();
				libCount.libraryName = libName;
				libCount.category = cat;
				libCount.numFindings = totalLibFindingsPerCategory.get(cat, libName);
				dbManager.addToDatabase(libCount);
			}
		}
	}

	/**
	 * Analyzes the jobs on the VUSC server for statistical data
	 * 
	 * @param vuscURL   The URL of the VUSC server on which to perform the
	 *                  statistical analysis
	 * @param dbManager The manager class for interacting with the database
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void analyzeVulnerabilitiesPerCategory2(String vuscURL, DatabaseManager dbManager)
			throws IOException, SQLException {
		doForEachJob(vuscURL, dbManager, (j, kAPI) -> {
			try {
				JobResults results = j.getJobResults();
				if (results != null) {
					List<VulnerabilityFinding> vulnFindings = results.getVulnerabilityFindings();
					if (vulnFindings != null && !vulnFindings.isEmpty()) {
						CountingTable<String, String> findingsAndCategories = new CountingTable<>();

						// Count the vulnerabilities and categories
						for (VulnerabilityFinding finding : vulnFindings)
							findingsAndCategories.increment(finding.getCategory(), finding.getType());

						// Report the findings per category
						for (String cat : findingsAndCategories.rowKeySet()) {
							for (String vuln : findingsAndCategories.columnKeySet()) {
								int count = findingsAndCategories.get(cat, vuln);
								if (count > 0) {
									PerCategoryFindingCount dbObject = new PerCategoryFindingCount();
									dbObject.jobId = j.getId();
									dbObject.category = cat;
									dbObject.vulnerability = vuln;
									dbObject.count = count;
									dbManager.addToDatabase(dbObject);
								}
							}
						}
					}
				}
			} catch (SQLException | IOException ex) {
				logger.error(String.format("Could not obtain analysis jobs from %s", vuscURL), ex);
			}
		});
	}

	/**
	 * Computes statistics on crypto algorithm use (calls to crypto APIs inside the
	 * application code)
	 * 
	 * @param vuscURL   The URL of the VUSC server on which to perform the
	 *                  statistical analysis
	 * @param dbManager The manager class for interacting with the database
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void analyzeCryptoStats1(String vuscURL, DatabaseManager dbManager)
			throws IOException, SQLException {
		doForEachJob(vuscURL, dbManager, (j, kAPI) -> {
			try {
				JobResults results = j.getJobResults();
				if (results != null) {
					List<InformationFinding> infoFindings = results.getInformationFindings();
					if (infoFindings != null && !infoFindings.isEmpty()) {
						CountingMap<String> findingsPerAlgo = new CountingMap<>();
						for (InformationFinding finding : infoFindings) {
							switch (finding.getType()) {
							case "CryptoStatistics_CipherStatistics":
							case "CryptoStatistics_DigestStatistics":
								List<AdditionalData> additionalData = finding.getAdditionalData();
								if (additionalData != null && !additionalData.isEmpty()) {
									for (AdditionalData data : additionalData) {
										findingsPerAlgo.increment(data.getName(), Integer.valueOf(data.getData()));
									}
								}
								break;
							}
						}

						if (!findingsPerAlgo.isEmpty()) {
							CryptoStatistics dbObject = new CryptoStatistics();
							dbObject.jobId = j.getId();
//							dbObject.totalCiphers = findingsPerAlgo.sum();
							dbObject.numMd5 = findingsPerAlgo.get("MD5") + findingsPerAlgo.get("md5");
							dbObject.numRc4 = findingsPerAlgo.get("RC4");
							dbObject.numSha1 = findingsPerAlgo.get("sha1") + findingsPerAlgo.get("SHA1")
									+ findingsPerAlgo.get("SHA-1");
							dbObject.numSha256 = findingsPerAlgo.get("SHA-256");
							dbObject.numSha512 = findingsPerAlgo.get("SHA-512");
							dbObject.numAes = findingsPerAlgo.get("AES");
							dbObject.numDsa = findingsPerAlgo.get("DSA");
							dbObject.numRsa = findingsPerAlgo.get("RSA");
							dbObject.numBlowfish = findingsPerAlgo.get("Blowfish");
							dbManager.addToDatabase(dbObject);
						}
					}
				}
			} catch (SQLException | IOException ex) {
				logger.error(String.format("Could not obtain analysis jobs from %s", vuscURL), ex);
			}
		});
	}

	/**
	 * Computes statistics on which outdated crypto algorithms are used in the apps
	 * 
	 * @param vuscURL   The URL of the VUSC server on which to perform the
	 *                  statistical analysis
	 * @param dbManager The manager class for interacting with the database
	 * @throws SQLException
	 * @throws IOException
	 */
	private static void analyzeCryptoStats2(String vuscURL, DatabaseManager dbManager)
			throws IOException, SQLException {
		CountingTable<String, String> totalAlgosInLibs = new CountingTable<>();
		doForEachJob(vuscURL, dbManager, (j, kAPI) -> {
			try {
				JobResults results = j.getJobResults();
				if (results != null) {
					List<VulnerabilityFinding> vulnFindings = results.getVulnerabilityFindings();
					if (vulnFindings != null && !vulnFindings.isEmpty()) {
						CountingMap<String> algoMap = new CountingMap<>();
						CountingTable<String, String> algosInLibs = new CountingTable<>();
						for (VulnerabilityFinding finding : vulnFindings) {
							if (finding.getType() != null
									&& finding.getType().equals("CryptoCheckAnalysis_InsecureCryptoAlgorithm")) {
								// Check for library use
								List<UsedLibrary> libInfo = null;
								if (finding.getLocation() instanceof CodeLocation) {
									CodeLocation codeLoc = (CodeLocation) finding.getLocation();
									libInfo = kAPI.getLibrariesByClassName(codeLoc.getClassName());
								}

								List<AdditionalData> additionalData = finding.getAdditionalData();
								if (additionalData != null && !additionalData.isEmpty()) {
									for (AdditionalData data : additionalData) {
										if (data.getName() != null && data.getName().equalsIgnoreCase("ALGORITHM")) {
											algoMap.increment(data.getData());
											if (libInfo != null && !libInfo.isEmpty())
												algosInLibs.increment(data.getData(),
														libInfo.iterator().next().getName());
										}
									}
								}
							}
						}

						for (String algo : algoMap.keySet()) {
							Integer numFindings = algoMap.get(algo);
							Integer libFindings = algosInLibs.rowSum(algo);

							OutdatedAlgorithmStatistics stats = new OutdatedAlgorithmStatistics();
							stats.jobId = j.getId();
							stats.algorithm = algo;
							stats.count = numFindings;
							if (numFindings != null && libFindings != null && numFindings != 0 && libFindings != 0)
								stats.libraryPercentage = libFindings / numFindings;
							dbManager.addToDatabase(stats);
						}

						totalAlgosInLibs.addAll(algosInLibs);
					}
				}
			} catch (SQLException | IOException | ApiException ex) {
				logger.error(String.format("Could not obtain analysis jobs from %s", vuscURL), ex);
			}
		});

		for (String libName : totalAlgosInLibs.columnKeySet()) {
			for (String algo : totalAlgosInLibs.rowKeySet()) {
				LibraryCryptoCount libCount = new LibraryCryptoCount();
				libCount.libraryName = libName;
				libCount.algorithm = algo;
				libCount.numFindings = totalAlgosInLibs.get(algo, libName);
				dbManager.addToDatabase(libCount);
			}
		}
	}

	/**
	 * Submits the applications from the given APK file listing as new jobs to the
	 * VUSC server
	 * 
	 * @param appFiles The path to a text file that contains the paths to the
	 *                 individual APK files
	 * @param vuscURL  The URL of the VUSC server on which to schedule the analyses
	 * @throws IOException
	 */
	private static void submitJobs(String appFiles, String vuscURL) throws IOException {
		ApiClient client = new ApiClient();
		client.setBasePath(vuscURL);
		JobsApi jobs = new JobsApi(client);
		List<String> apkFiles = Files.readAllLines(Paths.get(appFiles));
		for (String apk : apkFiles) {
			if (!apk.isEmpty()) {
				try {
					jobs.createJob(new File(apk), null);
				} catch (ApiException ex) {
					logger.error(String.format("Could not schedule analysis for %s", apk), ex);
				}
			}
		}
	}

	/**
	 * Computes the app metadata for all apps contained in the given list file
	 * 
	 * @param appFiles  The path to a text file that contains the paths of the
	 *                  individual apps
	 * @param year      The year with which the apps can be associated
	 * @param dbManager The manager for interacting with the database
	 * @throws IOException
	 * @throws SQLException
	 */
	private static void computeAppMetadata(String appFiles, Integer year, DatabaseManager dbManager)
			throws IOException, SQLException {
		List<String> apkFiles = Files.readAllLines(Paths.get(appFiles));
		for (String apk : apkFiles) {
			if (!apk.isEmpty()) {
				AppToAnalyze app = new AppToAnalyze();
				app.apkFileName = apk;
				app.year = year;
				try (FileInputStream fis = new FileInputStream(apk)) {
					app.sha256hash = DigestUtils.sha256Hex(fis);
				}
				dbManager.addToDatabase(app);
			}
		}
	}

}
