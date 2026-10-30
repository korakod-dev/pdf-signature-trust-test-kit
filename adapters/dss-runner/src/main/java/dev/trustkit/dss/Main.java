package dev.trustkit.dss;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Validates one PDF with the unmodified default DSS policy and writes the raw reports.
 *
 * <p>Trusts only the given certificate. Online sources are set so that revocation cases can reach
 * the loopback service. Only certificates with URLs fetch, and the fixtures' URLs are on loopback.
 * Interpreting the reports is left to the Python adapter and the mapping.
 *
 * <p>Usage: {@code --version}, or {@code <pdf> <trust anchor> <output directory>}.
 */
public final class Main {
    private static final String DSS_PROPERTIES =
            "META-INF/maven/eu.europa.ec.joinup.sd-dss/dss-validation/pom.properties";

    private Main() {}

    public static void main(String[] args) throws IOException {
        if (args.length == 1 && args[0].equals("--version")) {
            System.out.println("dss=" + dssVersion());
            System.out.println("java=" + System.getProperty("java.version"));
            return;
        }
        if (args.length != 3) {
            System.err.println("usage: --version | <pdf> <trust anchor> <output directory>");
            System.exit(99);
        }

        DSSDocument document = new FileDocument(new File(args[0]));
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(DSSUtils.loadCertificate(new File(args[1])));
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trusted);
        verifier.setCrlSource(new OnlineCRLSource());
        verifier.setOcspSource(new OnlineOCSPSource());
        verifier.setAIASource(new DefaultAIASource());

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
        validator.setCertificateVerifier(verifier);
        Reports reports = validator.validateDocument();

        Path out = Path.of(args[2]);
        Files.createDirectories(out);
        Files.writeString(out.resolve("simple.xml"), reports.getXmlSimpleReport(), StandardCharsets.UTF_8);
        Files.writeString(out.resolve("diagnostic.xml"), reports.getXmlDiagnosticData(), StandardCharsets.UTF_8);
    }

    private static String dssVersion() throws IOException {
        try (InputStream stream = Main.class.getClassLoader().getResourceAsStream(DSS_PROPERTIES)) {
            if (stream == null) {
                throw new IOException("missing " + DSS_PROPERTIES);
            }
            Properties properties = new Properties();
            properties.load(stream);
            return properties.getProperty("version");
        }
    }
}
