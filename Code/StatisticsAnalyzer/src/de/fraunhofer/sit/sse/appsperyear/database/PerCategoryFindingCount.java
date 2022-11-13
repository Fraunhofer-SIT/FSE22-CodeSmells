package de.fraunhofer.sit.sse.appsperyear.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "PerCategoryFindingCount")
public class PerCategoryFindingCount {

	@DatabaseField(generatedId = true)
	public int id;

	@DatabaseField
	public Long jobId;

	@DatabaseField
	public String category;

	@DatabaseField
	public String vulnerability;

	@DatabaseField
	public int count;

}
