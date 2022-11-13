package de.fraunhofer.sit.sse.appsperyear.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "LibraryCryptoCount")
public class LibraryCryptoCount {

	@DatabaseField(generatedId = true)
	public int id;

	@DatabaseField(uniqueCombo = true)
	public String libraryName;

	@DatabaseField(uniqueCombo = true)
	public String algorithm;

	@DatabaseField
	public int numFindings;

}
