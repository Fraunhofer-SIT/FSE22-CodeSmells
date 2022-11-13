package de.fraunhofer.sit.sse.appsperyear.database;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "CryptoStatistics")
public class CryptoStatistics {

	@DatabaseField(generatedId = true)
	public int id;

	@DatabaseField(uniqueCombo = true)
	public Long jobId;

	@DatabaseField
	public int totalCiphers;

	@DatabaseField
	public int numMd5;

	@DatabaseField
	public int numRc4;

	@DatabaseField
	public int numSha1;

	@DatabaseField
	public int numSha256;

	@DatabaseField
	public int numSha512;

	@DatabaseField
	public int numAes;

	@DatabaseField
	public int numDsa;

	@DatabaseField
	public int numRsa;

	@DatabaseField
	public int numBlowfish;

}
