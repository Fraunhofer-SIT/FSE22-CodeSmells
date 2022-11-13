package de.fraunhofer.sit.sse.appsperyear.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * A job on which the vulnerability sets have been computed
 * 
 * @author Steven Arzt
 *
 */
@DatabaseTable(tableName = "AppsToAnalyze")
public class AppToAnalyze {

	@DatabaseField(generatedId = true)
	public int id;

	@DatabaseField(unique = true)
	public Long jobId;

	@DatabaseField(canBeNull = false)
	public int year;

	@DatabaseField(canBeNull = false)
	public String apkFileName;

	@DatabaseField(canBeNull = false, unique = true, index = true)
	public String sha256hash;

	@DatabaseField(index = true)
	public String packageName;

	@DatabaseField
	public String versionName;

	@DatabaseField
	public int numClasses;

	@DatabaseField
	public int numMethods;

	@DatabaseField
	public int numUnits;

	@DatabaseField
	public int numLibClasses;

	@DatabaseField
	public int numAppClasses;

}
