package com.example.xmlsign;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Command-line entry point to sign an XML file using the Sgntr/Signature algorithm set.
 * Uses the .p12 keystore from the resources folder (keystore.p12).
 * <p>
 * Usage:
 * <pre>
 *   java -cp ... com.example.xmlsign.Main &lt;input-xml&gt; [password] [output-xml]
 * </pre>
 * Keystore: place keystore.p12 in src/main/resources. If output is omitted, signed XML is printed to stdout.
 */
public final class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: Main <input-xml> [password] [output-xml]");
            System.err.println("  Keystore: put keystore.p12 in src/main/resources");
            System.err.println("  password defaults to 'changeit' if omitted");
            System.exit(1);
        }

        Path inputPath = Paths.get(args[0]).toAbsolutePath();
        char[] password = args.length > 1 ? args[1].toCharArray() : "changeit".toCharArray();
        Path outputPath = args.length > 2 ? Paths.get(args[2]).toAbsolutePath() : null;

        if (!Files.isRegularFile(inputPath)) {
            System.err.println("Input file not found: " + inputPath);
            System.exit(1);
        }

        String inputXml = Files.readString(inputPath, StandardCharsets.UTF_8);
        String signedXml = XmlSigner.signXmlFromResource(inputXml, XmlSigner.DEFAULT_KEYSTORE_RESOURCE, password);

        if (outputPath != null) {
            Files.writeString(outputPath, signedXml, StandardCharsets.UTF_8);
            System.out.println("Signed XML written to: " + outputPath);
        } else {
            System.out.println(signedXml);
        }
    }
}
