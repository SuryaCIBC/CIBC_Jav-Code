package com.example.xmlsignapi.service;

import com.example.xmlsign.XmlSigner;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Service that delegates XML signing to the java-xml-sign library.
 * Uses keystore and password from configuration.
 */
@Service
public class XmlSignService {

    @Value("${xmlsign.keystore-resource:keystore.p12}")
    private String keystoreResource;

    @Value("${xmlsign.keystore-password:changeit}")
    private String keystorePassword;

    /**
     * Signs the given XML using the configured PKCS12 keystore from classpath (resources).
     *
     * @param xmlPayload the XML document to sign (UTF-8)
     * @return signed XML with Sgntr/Signature inside AppHdr
     */
    public String sign(String xmlPayload) throws Exception {
        return XmlSigner.signXmlFromResource(
                xmlPayload,
                keystoreResource,
                keystorePassword.toCharArray()
        );
    }
}
