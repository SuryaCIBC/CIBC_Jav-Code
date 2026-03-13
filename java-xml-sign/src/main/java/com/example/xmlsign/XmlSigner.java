package com.example.xmlsign;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Signs XML using the algorithms defined in the Sgntr/Signature structure: -
 * CanonicalizationMethod: REC-xml-c14n-20010315 (C14N 1.0) - SignatureMethod:
 * rsa-sha256 - Reference URI="", Transforms: enveloped-signature, then C14N 1.1
 * - DigestMethod: sha256
 */
public final class XmlSigner {

	static {
		Init.init();
	}
	private static final ZoneId BARBADOS_ZONE = ZoneId.of("America/Barbados");

	private static final DateTimeFormatter ISO_OFFSET = DateTimeFormatter.ISO_OFFSET_DATE_TIME; // e.g.,
																								// 2026-02-26T14:44:14-04:00
	private static final DateTimeFormatter ISO_INSTANT = DateTimeFormatter.ISO_INSTANT; // e.g., 2026-02-26T18:44:14Z
	private static final DateTimeFormatter YMD_WITH_OFFSET = DateTimeFormatter.ofPattern("yyyy-MM-ddXXX"); // e.g.,
																											// 2026-02-26-04:00
	

	// ✅ Supports Instant directly and prints Z with EXACTLY 7 fractional digits
	private static final DateTimeFormatter ISO_INSTANT_7 =
	        new DateTimeFormatterBuilder()
	            .appendInstant(7)
	            .toFormatter();

	

	// UTC Z with EXACTLY 7 fractional digits (e.g., ...14.1252419Z)
	private static final DateTimeFormatter ISO_INSTANT_7NANOS =
	        new DateTimeFormatterBuilder()
	            .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
	            .appendFraction(ChronoField.NANO_OF_SECOND, 7, 7, true)
	            .appendLiteral('Z')
	            .toFormatter();

	// Offset time with EXACTLY 7 fractional digits (e.g., ...14.1245536-04:00)
	private static final DateTimeFormatter ISO_OFFSET_7NANOS =
	        new DateTimeFormatterBuilder()
	            .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
	            .appendFraction(ChronoField.NANO_OF_SECOND, 7, 7, true)
	            .appendOffset("+HH:MM", "+00:00")
	            .toFormatter();


	/** Default keystore resource name in classpath (e.g. in src/main/resources). */
	public static final String DEFAULT_KEYSTORE_RESOURCE = "keystore.p12";

	/**
	 * Local name of the header element that must contain Sgntr (e.g. env:AppHdr).
	 */
	public static final String APPHDR_LOCAL_NAME = "AppHdr";

	/**
	 * Signs the XML document using the PKCS12 keystore from the classpath (e.g.
	 * from resources folder).
	 *
	 * @param inputXml         UTF-8 XML string
	 * @param keystoreResource classpath resource name (e.g. "keystore.p12")
	 * @param keystorePassword keystore password
	 * @return signed XML as string
	 */
	public static String signXmlFromResource(String inputXml, String keystoreResource, char[] keystorePassword)
			throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (InputStream is = XmlSigner.class.getClassLoader().getResourceAsStream(keystoreResource)) {
			if (is == null) {
				throw new IllegalArgumentException("Keystore not found on classpath: " + keystoreResource);
			}
			ks.load(is, keystorePassword);
		}
		String alias = ks.aliases().nextElement();
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(keystorePassword));
		return signXml(inputXml, entry.getPrivateKey(), (X509Certificate) entry.getCertificate());
	}

	/**
	 * Signs the XML document. The signature is placed inside a &lt;Sgntr&gt;
	 * element under the document root. Any existing &lt;Sgntr&gt; is replaced.
	 *
	 * @param inputXml         UTF-8 XML string
	 * @param pkcs12Path       path to PKCS12 keystore file
	 * @param keystorePassword keystore password
	 * @return signed XML as string
	 */
	public static String signXml(String inputXml, Path pkcs12Path, char[] keystorePassword) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (InputStream is = Files.newInputStream(pkcs12Path)) {
			ks.load(is, keystorePassword);
		}
		String alias = ks.aliases().nextElement();
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias,
				new KeyStore.PasswordProtection(keystorePassword));
		return signXml(inputXml, entry.getPrivateKey(), (X509Certificate) entry.getCertificate());
	}

	/**
	 * Signs the XML document using the provided private key and certificate.
	 * Signature is placed inside &lt;Sgntr&gt; under the document root.
	 */
	public static String signXml(String inputXml, PrivateKey privateKey, X509Certificate x509) throws Exception {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder()
				.parse(new java.io.ByteArrayInputStream(inputXml.getBytes(StandardCharsets.UTF_8)));

		setIncomingDateTimeFields2(doc);

		signDocument(doc, privateKey, x509);

		return documentToString(doc);
	}

	/**
	 * Signs the document in place. Puts &lt;Sgntr&gt; inside env:AppHdr (element
	 * with local name AppHdr). If AppHdr is not found, falls back to document root.
	 */
	public static void signDocument(Document doc, PrivateKey privateKey, X509Certificate x509) throws Exception {
		Element root = doc.getDocumentElement();
		if (root == null) {
			throw new IllegalArgumentException("Document has no root element");
		}

		Element appHdr = findElementByLocalName(root, APPHDR_LOCAL_NAME);
		Element sgntrParent = (appHdr != null) ? appHdr : root;

		// Remove any Sgntr from root so only one Sgntr exists (inside AppHdr)
		removeSgntrFromElement(doc, root);
		if (appHdr != null) {
			removeSgntrFromElement(doc, appHdr);
		}

		Element sgntr = ensureSgntr(doc, sgntrParent);
		removeExistingSignature(sgntr);

		stripWhitespaceOnlyTextNodes(root);

		// Digest over document with Sgntr present but empty (enveloped: verifier
		// removes Signature then C14N 1.1)
		String digestValue = computeDigestEnveloped(doc, XmlSignatureAlgorithms.TRANSFORM_C14N11);

		Element signatureEl = buildSignatureElement(doc, digestValue, privateKey, x509);
		sgntr.appendChild(signatureEl);

		computeAndSetSignatureValue(doc, signatureEl, privateKey);
	}

	private static Element findElementByLocalName(Element root, String localName) {
		if (localName.equals(root.getLocalName())) {
			return root;
		}
		NodeList children = root.getChildNodes();
		for (int i = 0; i < children.getLength(); i++) {
			Node n = children.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE) {
				Element found = findElementByLocalName((Element) n, localName);
				if (found != null)
					return found;
			}
		}
		return null;
	}

	private static void removeSgntrFromElement(Document doc, Element parent) {
		NodeList children = parent.getChildNodes();
		for (int i = children.getLength() - 1; i >= 0; i--) {
			Node n = children.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE && "Sgntr".equals(n.getLocalName())) {
				parent.removeChild(n);
			}
		}
	}

	private static Element ensureSgntr(Document doc, Element parent) {
		NodeList children = parent.getChildNodes();
		for (int i = 0; i < children.getLength(); i++) {
			Node n = children.item(i);
			if (n.getNodeType() == Node.ELEMENT_NODE && "Sgntr".equals(n.getLocalName())) {
				return (Element) n;
			}
		}
		Element sgntr = doc.createElement("Sgntr");
		parent.appendChild(sgntr);
		return sgntr;
	}

	private static void removeExistingSignature(Element sgntr) {
		NodeList list = sgntr.getElementsByTagNameNS(XmlSignatureAlgorithms.SIGNATURE_NS, "Signature");
		if (list.getLength() == 0)
			return;
		Element sig = (Element) list.item(0);
		sgntr.removeChild(sig);
	}

	private static void stripWhitespaceOnlyTextNodes(Node node) {
		Node child = node.getFirstChild();
		while (child != null) {
			Node next = child.getNextSibling();
			if (child.getNodeType() == Node.TEXT_NODE) {
				String text = child.getTextContent();
				if (text != null && text.trim().isEmpty()) {
					node.removeChild(child);
				}
			} else if (child.getNodeType() == Node.ELEMENT_NODE) {
				stripWhitespaceOnlyTextNodes(child);
			}
			child = next;
		}
	}

	private static String computeDigestEnveloped(Document doc, String c14n11Algo) throws Exception {
		Canonicalizer canon = Canonicalizer.getInstance(c14n11Algo);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		canon.canonicalizeSubtree(doc.getDocumentElement(), baos);
		byte[] hash = MessageDigest.getInstance("SHA-256").digest(baos.toByteArray());
		return Base64.getEncoder().encodeToString(hash);
	}

	private static Element buildSignatureElement(Document doc, String digestValue, PrivateKey privateKey,
			X509Certificate x509) {
		String ns = XmlSignatureAlgorithms.SIGNATURE_NS;

		Element signature = doc.createElementNS(ns, "Signature");

		// SignedInfo
		Element signedInfo = doc.createElementNS(ns, "SignedInfo");

		Element canonMethod = doc.createElementNS(ns, "CanonicalizationMethod");
		canonMethod.setAttribute("Algorithm", XmlSignatureAlgorithms.CANONICALIZATION_METHOD);
		signedInfo.appendChild(canonMethod);

		Element sigMethod = doc.createElementNS(ns, "SignatureMethod");
		sigMethod.setAttribute("Algorithm", XmlSignatureAlgorithms.SIGNATURE_METHOD);
		signedInfo.appendChild(sigMethod);

		Element reference = doc.createElementNS(ns, "Reference");
		reference.setAttribute("URI", "");

		Element transforms = doc.createElementNS(ns, "Transforms");
		Element t1 = doc.createElementNS(ns, "Transform");
		t1.setAttribute("Algorithm", XmlSignatureAlgorithms.TRANSFORM_ENVELOPED_SIGNATURE);
		Element t2 = doc.createElementNS(ns, "Transform");
		t2.setAttribute("Algorithm", XmlSignatureAlgorithms.TRANSFORM_C14N11);
		transforms.appendChild(t1);
		transforms.appendChild(t2);
		reference.appendChild(transforms);

		Element digestMethod = doc.createElementNS(ns, "DigestMethod");
		digestMethod.setAttribute("Algorithm", XmlSignatureAlgorithms.DIGEST_METHOD);
		Element digestValueEl = doc.createElementNS(ns, "DigestValue");
		digestValueEl.setTextContent(digestValue);
		reference.appendChild(digestMethod);
		reference.appendChild(digestValueEl);

		signedInfo.appendChild(reference);
		signature.appendChild(signedInfo);

		Element signatureValue = doc.createElementNS(ns, "SignatureValue");
		signatureValue.setTextContent("");
		signature.appendChild(signatureValue);

		// KeyInfo
		Element keyInfo = doc.createElementNS(ns, "KeyInfo");
		Element x509Data = doc.createElementNS(ns, "X509Data");
		Element subjectName = doc.createElementNS(ns, "X509SubjectName");
		subjectName.setTextContent(x509.getSubjectX500Principal().getName());
		Element issuerSerial = doc.createElementNS(ns, "X509IssuerSerial");
		Element issuerName = doc.createElementNS(ns, "X509IssuerName");
		issuerName.setTextContent(formatX500Name(x509.getIssuerX500Principal().getName()));
		Element serialNumber = doc.createElementNS(ns, "X509SerialNumber");
		serialNumber.setTextContent(x509.getSerialNumber().toString());
		issuerSerial.appendChild(issuerName);
		issuerSerial.appendChild(serialNumber);
		x509Data.appendChild(subjectName);
		x509Data.appendChild(issuerSerial);
		keyInfo.appendChild(x509Data);
		signature.appendChild(keyInfo);

		return signature;
	}

	private static void computeAndSetSignatureValue(Document doc, Element signatureElement, PrivateKey privateKey)
			throws Exception {
		NodeList list = signatureElement.getElementsByTagNameNS(XmlSignatureAlgorithms.SIGNATURE_NS, "SignedInfo");
		Element signedInfo = (Element) list.item(0);

		Canonicalizer canon = Canonicalizer.getInstance(XmlSignatureAlgorithms.CANONICALIZATION_METHOD);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		canon.canonicalizeSubtree(signedInfo, baos);
		byte[] signedInfoBytes = baos.toByteArray();

		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(privateKey);
		signer.update(signedInfoBytes);
		byte[] signatureBytes = signer.sign();
		String signatureValueStr = Base64.getEncoder().encodeToString(signatureBytes);

		NodeList sigValList = signatureElement.getElementsByTagNameNS(XmlSignatureAlgorithms.SIGNATURE_NS,
				"SignatureValue");
		sigValList.item(0).setTextContent(signatureValueStr);
	}

	/**
	 * Format X509 name with space after commas (e.g. "C=EC, O=Montran, CN=...").
	 */
	private static String formatX500Name(String name) {
		if (name == null)
			return "";
		return name.replaceAll(",(?=[A-Za-z])", ", ");
	}

	private static String documentToString(Document doc) throws Exception {
		javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
		javax.xml.transform.Transformer t = tf.newTransformer();
		t.setOutputProperty(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "yes");
		t.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes");
		t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
		java.io.StringWriter w = new java.io.StringWriter();
		t.transform(new javax.xml.transform.dom.DOMSource(doc), new javax.xml.transform.stream.StreamResult(w));
		String xml = w.toString();
		// Empty elements: use " />" instead of "/>"
		return xml.replaceAll("/>", " />");
	}



private static void setIncomingDateTimeFields(Document doc) {
    // 1) One authoritative instant from Barbados NTP
    Instant ntpInstant = BarbadosTimeUtil.getNtpInstantOrNow();

    // 2) Barbados time from the same instant
    ZonedDateTime barbadosNow = ntpInstant.atZone(BARBADOS_ZONE);

    // 3) Format values EXACTLY as requested
    String creDt         = ISO_INSTANT_7.format(ntpInstant);       // e.g., 2026-02-26T18:44:14.1252419Z
    String creDtTm       = ISO_OFFSET_7NANOS.format(barbadosNow);  // e.g., 2026-02-26T14:44:14.1245536-04:00
    String accptncDtTm   = creDtTm;                                // same as CreDtTm
    String intrBkSttlmDt = barbadosNow.format(YMD_WITH_OFFSET);    // e.g., 2026-02-26-04:00

    // (Optional) Debug
    System.out.println("CreDt         : " + creDt);
    System.out.println("CreDtTm       : " + creDtTm);
    System.out.println("IntrBkSttlmDt : " + intrBkSttlmDt);
    System.out.println("AccptncDtTm   : " + accptncDtTm);

    // 4) Write into XML (namespace-agnostic helper)
    setFirstElementTextByLocalName(doc.getDocumentElement(), "CreDt", creDt.trim());
    setFirstElementTextByLocalName(doc.getDocumentElement(), "CreDtTm", creDtTm.trim());
    setFirstElementTextByLocalName(doc.getDocumentElement(), "IntrBkSttlmDt", intrBkSttlmDt.trim());
    setFirstElementTextByLocalName(doc.getDocumentElement(), "AccptncDtTm", accptncDtTm.trim());
}


	private static boolean setFirstElementTextByLocalName(Node node, String localName, String text) {
		if (node.getNodeType() == Node.ELEMENT_NODE && localName.equals(((Element) node).getLocalName())) {
			((Element) node).setTextContent(text);
			return true;
		}
		Node child = node.getFirstChild();
		while (child != null) {
			if (setFirstElementTextByLocalName(child, localName, text)) {
				return true;
			}
			child = child.getNextSibling();
		}
		return false;
	}
	
	private static void setIncomingDateTimeFields2(Document doc) {
		ZoneId BARBADOS_ZONE = ZoneId.of("America/Barbados");
		Instant nowUtc = Instant.now().truncatedTo(ChronoUnit.SECONDS);
		ZonedDateTime barbadosNow = nowUtc.atZone(BARBADOS_ZONE);
		LocalDate today = LocalDate.now(BARBADOS_ZONE);

		String creDt = DateTimeFormatter.ISO_INSTANT.format(nowUtc);
		String creDtTm = barbadosNow.withNano(0).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
		String intrBkSttlmDt = today.format(DateTimeFormatter.ISO_LOCAL_DATE);
		String accptncDtTm = creDtTm;

		setFirstElementTextByLocalName(doc.getDocumentElement(), "CreDt", creDt);
		setFirstElementTextByLocalName(doc.getDocumentElement(), "CreDtTm", creDtTm);
		setFirstElementTextByLocalName(doc.getDocumentElement(), "IntrBkSttlmDt", intrBkSttlmDt);
		setFirstElementTextByLocalName(doc.getDocumentElement(), "AccptncDtTm", accptncDtTm);
	}
}
