# XML Sign REST API

Spring Boot REST API for signing XML documents. Uses the [java-xml-sign](../java-xml-sign) library and the same XMLDSig algorithms (C14N 1.0, RSA-SHA256, enveloped-signature, C14N 1.1, SHA-256). Signature is placed inside `env:AppHdr` in a `<Sgntr>` element.

## Prerequisites

1. **Build and install the java-xml-sign library** (required for the dependency):

   ```bash
   cd ../java-xml-sign
   mvn clean install
   cd ../xml-sign-api
   ```

2. **Keystore**: Place your `keystore.p12` in `src/main/resources/`. The API uses it from the classpath (same as java-xml-sign).

## Build and run

```bash
mvn spring-boot:run
```

Or build a JAR and run:

```bash
mvn clean package
java -jar target/xml-sign-api-1.0.0.jar
```

Server runs on **http://localhost:8080** by default.

## API

### POST /api/sign

Signs the request body as XML and returns the signed XML.

| Item        | Value |
|------------|--------|
| **Request**  | Body: raw XML (e.g. ISO 20022 message with `env:Message` / `env:AppHdr`). |
| **Content-Type** | `application/xml` or `text/xml` |
| **Response** | Signed XML (same structure with `<Sgntr>` inside `env:AppHdr`). |
| **Response Content-Type** | `application/xml` |

**Example (PowerShell):**

```powershell
$xml = Get-Content -Path "path/to/your-message.xml" -Raw
Invoke-RestMethod -Uri "http://localhost:8080/api/sign" -Method Post -Body $xml -ContentType "application/xml"
```

**Example (curl):**

```bash
curl -X POST http://localhost:8080/api/sign \
  -H "Content-Type: application/xml" \
  -d @your-message.xml
```

## Configuration

In `application.properties` (or environment variables):

| Property | Default | Description |
|----------|---------|--------------|
| `server.port` | 8080 | Server port |
| `xmlsign.keystore-resource` | keystore.p12 | Classpath resource name for the PKCS12 keystore |
| `xmlsign.keystore-password` | changeit | Keystore password |

Example override:

```properties
xmlsign.keystore-password=your-secure-password
```

## Project layout

- `XmlSignApiApplication.java` – Spring Boot entry point
- `controller/XmlSignController.java` – REST endpoint `POST /api/sign`
- `service/XmlSignService.java` – Delegates to `com.example.xmlsign.XmlSigner`
- `exception/GlobalExceptionHandler.java` – Error responses for invalid requests / signing failures

The signing logic (algorithms, digest, placement of `<Sgntr>` inside AppHdr) is entirely in the **java-xml-sign** module; this project only exposes it over HTTP.
