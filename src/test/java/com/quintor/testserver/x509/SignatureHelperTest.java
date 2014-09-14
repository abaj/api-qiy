package com.quintor.testserver.x509;

import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author rhegge
 */
public class SignatureHelperTest {
    private static final String initialXml = "<xmldata><thingOne>something</thingOne><thingTwo>something</thingTwo></xmldata>";
    private String signedXml="";
    
    @Before
    public void setUp() {
        SignatureHelper.setKeyStoreDir("src/main/resources/");
        signedXml = SignatureHelper.signDocument(initialXml);
    }
    
    @After
    public void tearDown() {
    }
    
    /**
     * Tests whether the signed document is correctly signed and whether it 
     * parses back to the original state.
     * 
     * @throws SignatureVerificationException 
     */
    @Test
    public void parseSignatureTest() throws SignatureVerificationException
    {
        String parsedXml=SignatureHelper.parseSignature(signedXml, false);
        assertEquals(initialXml, parsedXml);
    }
}