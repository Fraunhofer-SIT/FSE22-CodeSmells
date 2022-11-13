package de.fraunhofer.sit.sse.appsperyear.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "OutdatedAlgorithmStatistics")
public class OutdatedAlgorithmStatistics {

	@DatabaseField(generatedId = true)
	public int id;

	@DatabaseField(uniqueCombo = true)
	public Long jobId;

	@DatabaseField(uniqueCombo = true)
	public String algorithm;

	@DatabaseField
	public int count;

	@DatabaseField
	public float libraryPercentage;

}
