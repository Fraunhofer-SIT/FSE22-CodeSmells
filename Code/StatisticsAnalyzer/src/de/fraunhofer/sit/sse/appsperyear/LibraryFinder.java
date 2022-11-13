package de.fraunhofer.sit.sse.appsperyear;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import de.codeinspect.collections.CountingMap;
import de.codeinspect.collections.EnumerationIterable;

public class LibraryFinder {

	private static final Pattern LIB_PATTERN = Pattern.compile("^lib\\/(?<platform>.+)\\/(?<libname>.+)\\.so$");

	public static void main(String[] args) throws IOException {
		CountingMap<String> libsPerAbi = new CountingMap<>();
		List<String> apkFiles = Files.readAllLines(new File(args[0]).toPath());
		for (String apk : apkFiles) {
			try (ZipFile zip = new ZipFile(apk)) {
				for (ZipEntry entry : new EnumerationIterable<>(zip.entries())) {
					if (entry.getName().startsWith("lib/")) {
						Matcher matcher = LIB_PATTERN.matcher(entry.getName());
						if (matcher.matches()) {
							libsPerAbi.increment(matcher.group("platform"));
						}
					}
				}
			}
		}
		System.out.println("Total: " + libsPerAbi.sum());
		System.out.println("---- ABIs -----");
		for (String abi : libsPerAbi.keySet())
			System.out.println(abi + "\t" + libsPerAbi.get(abi));
	}

}
