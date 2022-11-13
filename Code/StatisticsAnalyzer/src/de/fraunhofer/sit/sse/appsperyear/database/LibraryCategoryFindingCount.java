package de.fraunhofer.sit.sse.appsperyear.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

/**
 * Database class for associating libraries with the number of findings in that
 * library for a particular category
 * 
 * @author Steven Arzt
 *
 */
@DatabaseTable(tableName = "LibraryCategoryFindingCount")
public class LibraryCategoryFindingCount {

	@DatabaseField(generatedId = true)
	public int id;

	@DatabaseField(uniqueCombo = true)
	public String libraryName;

	@DatabaseField(uniqueCombo = true)
	public String category;

	@DatabaseField
	public int numFindings;

}
