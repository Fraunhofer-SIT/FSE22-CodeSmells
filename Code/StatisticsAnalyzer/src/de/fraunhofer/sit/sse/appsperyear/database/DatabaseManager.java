package de.fraunhofer.sit.sse.appsperyear.database;

import java.io.IOException;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.j256.ormlite.dao.CloseableIterator;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.stmt.QueryBuilder;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;

/**
 * Database manager for accessing the app metadata
 * 
 * @author Steven Arzt
 *
 */
public class DatabaseManager {

	private static Logger logger = LogManager.getLogger(DatabaseManager.class);

	private final String dbUrl;
	private final String userName;
	private final String password;

	public DatabaseManager(String dbUrl, String userName, String password) throws IOException, SQLException {
		this.dbUrl = dbUrl;
		this.userName = userName;
		this.password = password;

		ensureTables();
	}

	/**
	 * Ensures that all required tables exist
	 * 
	 * @throws SQLException
	 * @throws IOException
	 */
	private void ensureTables() throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			createTableSilently(cs, PerCategoryFindingCount.class);
			createTableSilently(cs, LibraryCategoryFindingCount.class);
			createTableSilently(cs, LibraryCryptoCount.class);
			createTableSilently(cs, LibraryFindingCount.class);
			createTableSilently(cs, OutdatedAlgorithmStatistics.class);
			createTableSilently(cs, CryptoStatistics.class);
			createTableSilently(cs, VulnerabilityCounts.class);
			createTableSilently(cs, VulnerabilitiesPerCategory.class);
			createTableSilently(cs, AppToAnalyze.class);
		} catch (Exception ex) {
			logger.error("Could not create database tables", ex);
		}
	}

	private void createTableSilently(ConnectionSource cs, Class<?> clazz) {
		try {
			TableUtils.createTableIfNotExists(cs, clazz);
		} catch (SQLException e) {
			logger.warn(String.format("Could not create table %s", clazz.getName()), e);
		}
	}

	/**
	 * Adds the given application metadata to the database
	 * 
	 * @param app The app data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(AppToAnalyze app) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<AppToAnalyze, String> dao = DaoManager.createDao(cs, AppToAnalyze.class);
			dao.create(app);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on vulnerabilities per category to the database
	 * 
	 * @param catVulns The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(VulnerabilitiesPerCategory catVulns) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<VulnerabilitiesPerCategory, String> dao = DaoManager.createDao(cs, VulnerabilitiesPerCategory.class);
			dao.create(catVulns);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on counts per vulnerability type to the database
	 * 
	 * @param vulnCounts The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(VulnerabilityCounts vulnCounts) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<VulnerabilityCounts, String> dao = DaoManager.createDao(cs, VulnerabilityCounts.class);
			dao.create(vulnCounts);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on crypto algorithm use to the database
	 * 
	 * @param cryptoStats The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(CryptoStatistics cryptoStats) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<CryptoStatistics, String> dao = DaoManager.createDao(cs, CryptoStatistics.class);
			dao.create(cryptoStats);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on crypto algorithm use to the database
	 * 
	 * @param stats The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(OutdatedAlgorithmStatistics stats) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<OutdatedAlgorithmStatistics, String> dao = DaoManager.createDao(cs, OutdatedAlgorithmStatistics.class);
			dao.create(stats);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on vulnerabilities in libraries to the database
	 * 
	 * @param stats The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(LibraryFindingCount stats) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<LibraryFindingCount, String> dao = DaoManager.createDao(cs, LibraryFindingCount.class);
			dao.create(stats);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on vulnerabilities in libraries to the database
	 * 
	 * @param stats The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(LibraryCategoryFindingCount stats) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<LibraryCategoryFindingCount, String> dao = DaoManager.createDao(cs, LibraryCategoryFindingCount.class);
			dao.create(stats);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on crypto algorithms used in libraries to the
	 * database
	 * 
	 * @param stats The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(LibraryCryptoCount stats) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<LibraryCryptoCount, String> dao = DaoManager.createDao(cs, LibraryCryptoCount.class);
			dao.create(stats);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Adds the given statistics on a pair of category and vulnerability to the
	 * database
	 * 
	 * @param stats The statistics data object
	 * @throws IOException
	 * @throws SQLException
	 */
	public void addToDatabase(PerCategoryFindingCount stats) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<PerCategoryFindingCount, String> dao = DaoManager.createDao(cs, PerCategoryFindingCount.class);
			dao.create(stats);
		} catch (Exception e) {
			logger.error("Could not add record to database", e);
		}
	}

	/**
	 * Gets the app with the given SHA256 hash from the database
	 * 
	 * @param sha256Hash The SHA256 hash over the input file
	 * @return The app with the given SHA256 hash
	 * @throws SQLException
	 * @throws IOException
	 */
	public AppToAnalyze getAppByHash(String sha256Hash) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<AppToAnalyze, String> dao = DaoManager.createDao(cs, AppToAnalyze.class);
			List<AppToAnalyze> apps = dao.queryForEq("sha256hash", sha256Hash);
			if (apps != null && !apps.isEmpty())
				return apps.get(0);
		} catch (Exception e) {
			logger.error("Could not get apps by hash", e);
		}
		return null;
	}

	/**
	 * Updates the given app record in the database
	 * 
	 * @param app The app record to update in the database
	 * @throws SQLException
	 * @throws IOException
	 */
	public void update(AppToAnalyze app) throws IOException, SQLException {
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<AppToAnalyze, String> dao = DaoManager.createDao(cs, AppToAnalyze.class);
			dao.update(app);
		} catch (Exception e) {
			logger.error("Could not update app record in database", e);
		}
	}

	/**
	 * Obtains all apps from the database
	 * 
	 * @return A collection with all apps in the database
	 * @throws IOException
	 * @throws SQLException
	 */
	public Set<AppToAnalyze> getAllApps() throws IOException, SQLException {
		Set<AppToAnalyze> allApps = new HashSet<>();
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<AppToAnalyze, String> dao = DaoManager.createDao(cs, AppToAnalyze.class);
			for (AppToAnalyze app : dao)
				allApps.add(app);
		} catch (Exception e) {
			logger.error("Could not retrieve all apps from database", e);
		}
		return allApps;
	}

	/**
	 * Obtains the apps for which there is no metadata yet from the database
	 * 
	 * @return A collection with the apps in the database that do not have metadata
	 *         yet
	 * @throws IOException
	 * @throws SQLException
	 */
	public Set<AppToAnalyze> getAppsWithoutMetadata() throws IOException, SQLException {
		Set<AppToAnalyze> allApps = new HashSet<>();
		try (ConnectionSource cs = new JdbcConnectionSource(dbUrl, userName, password)) {
			Dao<AppToAnalyze, String> dao = DaoManager.createDao(cs, AppToAnalyze.class);
			QueryBuilder<AppToAnalyze, String> queryBuilder = dao.queryBuilder();
			try (CloseableIterator<AppToAnalyze> it = queryBuilder.where().isNull("packageName").or()
					.isNull("versionName").iterator()) {
				while (it.hasNext())
					allApps.add(it.next());
			}
		} catch (Exception e) {
			logger.error("Could not retrieve apps without metadata from database", e);
		}
		return allApps;
	}

}
