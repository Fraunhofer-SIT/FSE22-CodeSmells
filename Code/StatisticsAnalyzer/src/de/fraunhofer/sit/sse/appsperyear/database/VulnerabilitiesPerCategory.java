package de.fraunhofer.sit.sse.appsperyear.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "VulnerabilitiesPerCategory")
public class VulnerabilitiesPerCategory {

	@DatabaseField(generatedId = true)
	public int id;

	@DatabaseField(uniqueCombo = true)
	public Long jobId;

	@DatabaseField(uniqueCombo = true)
	public String category;

	@DatabaseField
	public int numVulnerabilities;

	@DatabaseField
	public int numLibVulns;

	@DatabaseField
	public float libraryPercentage;

}
