# Java XML Sign (XMLDSig)

Sign XML using the algorithms defined in the `<Sgntr>` / `<Signature>` structure.

## Algorithms (from your spec)

| Component | Algorithm URI |
|-----------|----------------|
| **CanonicalizationMethod** | `http://www.w3.org/TR/2001/REC-xml-c14n-20010315` |
| **SignatureMethod** | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` |
| **Reference URI** | `""` (whole document) |
| **Transforms** | `enveloped-signature`, then `http://www.w3.org/2006/12/xml-c14n11` |
| **DigestMethod** | `http://www.w3.org/2001/04/xmlenc#sha256` |
| **KeyInfo** | X509SubjectName, X509IssuerSerial (X509IssuerName, X509SerialNumber) |

## Build

```bash
cd java-xml-sign
mvn clean package
```

## Keystore (required)

**Put your `.p12` file in the resources folder:**

- **Path:** `src/main/resources/keystore.p12`

The code loads the keystore from the classpath. To use a different filename, change `XmlSigner.DEFAULT_KEYSTORE_RESOURCE` or call `XmlSigner.signXmlFromResource(inputXml, "yourfile.p12", password)`.

To create a test keystore (then copy to `src/main/resources/`):

```bash
keytool -genkeypair -alias mykey -keyalg RSA -keysize 2048 -validity 365 \
  -keystore keystore.p12 -storetype PKCS12 -storepass changeit
```

## Run from command line

```bash
# Signed XML printed to stdout (uses src/main/resources/keystore.p12)
mvn exec:java -q -Dexec.mainClass="com.example.xmlsign.Main" \
  -Dexec.args="src/main/resources/sample.xml"

# With password and output file
mvn exec:java -q -Dexec.mainClass="com.example.xmlsign.Main" \
  -Dexec.args="src/main/resources/sample.xml changeit signed.xml"
```

Or with the JAR (after `mvn package`):

```bash
java -cp "target/java-xml-sign-1.0.0.jar;target/lib/*" com.example.xmlsign.Main ^
  src/main/resources/sample.xml changeit signed.xml
```

(On Unix use `:` instead of `;` in the classpath.)

## Use in code

```java
import com.example.xmlsign.XmlSigner;

// From .p12 in resources folder (e.g. src/main/resources/keystore.p12)
String signed = XmlSigner.signXmlFromResource(
    inputXml,
    XmlSigner.DEFAULT_KEYSTORE_RESOURCE,  // "keystore.p12"
    "changeit".toCharArray()
);

// From PKCS12 file path
String signed = XmlSigner.signXml(
    inputXml,
    Paths.get("path/to/keystore.p12"),
    "changeit".toCharArray()
);

// With existing PrivateKey and X509Certificate
String signed = XmlSigner.signXml(inputXml, privateKey, x509Certificate);
```

## Input XML

- The signer looks for a `<Sgntr>` element under the document root. If missing, it creates one.
- Any existing `<Signature>` inside `<Sgntr>` is removed before adding the new signature.
- The digest is computed over the whole document with `<Sgntr>` present but empty (enveloped-signature semantics).

## Dependencies

- **Apache Santuario (xmlsec)** 4.0.4 – XML Signature and C14N 1.1 support.
