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
    
    @Test
    public void parseSignatureTest() throws SignatureVerificationException
    {
        String parsedXml=SignatureHelper.parseSignature(signedXml, false);
        assertEquals(initialXml, parsedXml);
    }
}
/*
    //Temp break to verify a chain
                X509Certificate[] certs = new X509Certificate[3];
                KeyStore ks;
                ks = KeyStore.getInstance("JKS");
                ks.load(new FileInputStream("keystorebest.jks"), "changeit".toCharArray());
                KeyStore.TrustedCertificateEntry keyEntry = (KeyStore.TrustedCertificateEntry) ks.getEntry("server", null);
                X509Certificate certi = (X509Certificate) keyEntry.getTrustedCertificate();
                certs[0] = certi;
                keyEntry = (KeyStore.TrustedCertificateEntry) ks.getEntry("inter", null);
                certi = (X509Certificate) keyEntry.getTrustedCertificate();
                certs[1] = certi;
                keyEntry = (KeyStore.TrustedCertificateEntry) ks.getEntry("ca", null);
                certi = (X509Certificate) keyEntry.getTrustedCertificate();
                certs[2] = certi;

try {
                //Temp break to verify a chain
                //X509Certificate[] certs = new X509Certificate[3];
                KeyStore ks;
                ks = KeyStore.getInstance("JKS");
                ks.load(new FileInputStream("keystorebest.jks"), "changeit".toCharArray());
                KeyStore.TrustedCertificateEntry keyEntry = (KeyStore.TrustedCertificateEntry) ks.getEntry("server", null);

           // end temp break
                ks = KeyStore.getInstance("JKS");
                ks.load(new FileInputStream("cacerts.jks"), "changeit".toCharArray());
                // This class retrieves the most-trusted CAs from the keystore
                PKIXParameters params = new PKIXParameters(ks);
                ArrayList<X509Certificate> list = new ArrayList<>();
                list.add(certs[1]);
                list.add(certs[2]);
                // Get the set of trust anchors, which contain the most-trusted CA certificates
                Set<TrustAnchor> trustAnchors = params.getTrustAnchors();
                // Enable On-Line Certificate Status Protocol (OCSP) support
                Security.setProperty("ocsp.enable", "true");

                // Enable Certificate Revocation List Distribution Points (CRLDP) support
                System.setProperty("com.sun.security.enableCRLDP", "true");
                /* /*System.out.println(CertificateVerifier.verifyCertificate((X509Certificate) certs.toArray()[0], new HashSet<>(certs));/*);
                PKIXCertPathBuilderResult result = CertificateVerifier.verifyCertificate((X509Certificate) certs[0], trustAnchors,
                        new HashSet<>(list));

                System.out.println(result);

            } catch (GeneralSecurityException ex) {
                Logger.getLogger(X509KeySelector.class.getName()).log(Level.SEVERE, null, ex);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(X509KeySelector.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(X509KeySelector.class.getName()).log(Level.SEVERE, null, ex);
            }
            //pathBuilder(certs);
            Iterator xi = x509Data.getContent().iterator();
            while (xi.hasNext()) {
                Object o = xi.next();
                if (!(o instanceof X509Certificate)) {
                    continue;
                }
                final PublicKey key = ((X509Certificate) o).getPublicKey();
                // Make sure the algorithm is compatible
                // with the method.
                if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                    return new KeySelectorResult() {
                        public Key getKey() {
                            return key;
                        }
                    };
                }
            }
        }
        throw new KeySelectorException("No key found!");
    }



// Enable On-Line Certificate Status Protocol (OCSP) support
                Security.setProperty("ocsp.enable", "true");

                // Enable Certificate Revocation List Distribution Points (CRLDP) support
                System.setProperty("com.sun.security.enableCRLDP", "true");

pkixParams.setRevocationEnabled(true);
*/