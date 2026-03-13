package com.example.xmlsign;

/**
 * Algorithm URIs matching the XMLDSig structure:
 * CanonicalizationMethod, SignatureMethod, Transforms, DigestMethod.
 */
public final class XmlSignatureAlgorithms {

    /** SignedInfo canonicalization: http://www.w3.org/TR/2001/REC-xml-c14n-20010315 */
    public static final String CANONICALIZATION_METHOD =
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    /** Signature method: RSA-SHA256 */
    public static final String SIGNATURE_METHOD =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    /** Enveloped signature transform */
    public static final String TRANSFORM_ENVELOPED_SIGNATURE =
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    /** Canonical XML 1.1 transform for Reference */
    public static final String TRANSFORM_C14N11 =
            "http://www.w3.org/2006/12/xml-c14n11";

    /** Digest method: SHA-256 */
    public static final String DIGEST_METHOD =
            "http://www.w3.org/2001/04/xmlenc#sha256";

    /** XML Signature namespace */
    public static final String SIGNATURE_NS = "http://www.w3.org/2000/09/xmldsig#";

    private XmlSignatureAlgorithms() {}
}
