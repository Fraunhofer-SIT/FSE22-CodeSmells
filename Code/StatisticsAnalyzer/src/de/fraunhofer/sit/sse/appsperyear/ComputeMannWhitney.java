package de.fraunhofer.sit.sse.appsperyear;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import org.apache.commons.math3.stat.inference.MannWhitneyUTest;

public class ComputeMannWhitney {

	public static void main(String[] args) throws IOException {
		String fileA = args[0];
		String fileB = args[1];

		MannWhitneyUTest test = new MannWhitneyUTest();
		List<String> valuesA = Files.readAllLines(new File(fileA).toPath());
		List<String> valuesB = Files.readAllLines(new File(fileB).toPath());

		double[] valsA = new double[valuesA.size()];
		double[] valsB = new double[valuesB.size()];
		for (int i = 0; i < valuesA.size(); i++)
			valsA[i] = Double.valueOf(valuesA.get(i));
		for (int i = 0; i < valuesB.size(); i++)
			valsB[i] = Double.valueOf(valuesB.get(i));

		System.out.println("p-value: " + test.mannWhitneyUTest(valsA, valsB));
	}

}
