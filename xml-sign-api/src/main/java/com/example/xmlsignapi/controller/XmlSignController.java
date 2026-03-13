package com.example.xmlsignapi.controller;

import com.example.xmlsignapi.service.XmlSignService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API for XML signing. Accepts XML in the request body and returns signed XML.
 */
@RestController
@RequestMapping("/api")
public class XmlSignController {

    private final XmlSignService xmlSignService;

    public XmlSignController(XmlSignService xmlSignService) {
        this.xmlSignService = xmlSignService;
    }

    /**
     * Sign XML. Request body must be the raw XML document to sign.
     * Response is the same XML with Sgntr/Signature inserted inside env:AppHdr.
     *
     * Content-Type: application/xml or text/xml
     */
    @PostMapping(value = "/sign", consumes = { MediaType.APPLICATION_XML_VALUE, MediaType.TEXT_XML_VALUE }, produces = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> sign(@RequestBody String xmlBody) throws Exception {
        String signedXml = xmlSignService.sign(xmlBody);
        return ResponseEntity.ok(signedXml);
    }
}
