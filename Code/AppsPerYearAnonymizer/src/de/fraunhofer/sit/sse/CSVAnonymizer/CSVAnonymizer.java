package de.fraunhofer.sit.sse.CSVAnonymizer;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import soot.util.HashMultiMap;
import soot.util.MultiMap;

public class CSVAnonymizer {

	public static void main(String[] args) throws FileNotFoundException, IOException {
		MultiMap<String, String> yearToJobID = new HashMultiMap<>();
		Map<String, String> jobIDToYear = new HashMap<>();

		try (FileReader rdr = new FileReader(args[0]);
				CSVParser parser = CSVFormat.EXCEL.withFirstRecordAsHeader().parse(rdr);) {
			for (CSVRecord record : parser) {
				String jobid = record.get("jobId");
				String year = record.get("year");

				if (jobid != null && !jobid.isEmpty()) {
					yearToJobID.put(year, jobid);
					jobIDToYear.put(jobid, year);
				}
			}
		}

		Set<String> processedJobIds = new HashSet<>();

		Random rnd = new Random();
		try (FileReader rdr = new FileReader(args[0]);
				FileWriter wr = new FileWriter(args[1]);
				CSVParser parser = CSVFormat.EXCEL.withFirstRecordAsHeader().parse(rdr);
				CSVPrinter printer = new CSVPrinter(wr, CSVFormat.EXCEL);) {
			printer.printRecord(parser.getHeaderNames());
			for (CSVRecord record : parser) {
				Map<String, String> items = record.toMap();

				// Randomize the job ID
				String year = items.get("year");
				String oldJobId = items.get("jobId");
				if (oldJobId != null && !oldJobId.isEmpty() && processedJobIds.add(oldJobId)) {
					String jobId = pickRandomElement(yearToJobID.get(year), rnd);

					items.put("jobId", jobId);
					List<String> newRecord = new ArrayList<>();
					for (String hdr : parser.getHeaderNames())
						newRecord.add(items.get(hdr));
					printer.printRecord(newRecord);
				}
			}
		}
	}

	private static String pickRandomElement(Set<String> set, Random rnd) {
		List<String> elements = new ArrayList<>(set);
		String ret = elements.get(rnd.nextInt(elements.size()));
		set.remove(ret);
		return ret;
	}

}