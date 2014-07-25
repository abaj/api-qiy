package com.quintor.testserver.x509;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

/**
 *
 * @author rhegge
 */
public class X509KeySelector extends KeySelector {

    private String keyStoreDir;
    private boolean checkRevocation;
    
    @Override
    public KeySelectorResult select(KeyInfo keyInfo,
            KeySelector.Purpose purpose,
            AlgorithmMethod method,
            XMLCryptoContext context)
    throws KeySelectorException {
        Iterator ki = keyInfo.getContent().iterator();
        while (ki.hasNext()) {
//            for(XMLStructure info : keyInfo.getContent())
            XMLStructure info = (XMLStructure) ki.next();
            if (!(info instanceof X509Data)) {
                continue;
            }
            X509Data x509Data = (X509Data) info;
            List<X509Certificate> certs = (List<X509Certificate>) x509Data.getContent();
            try {
                KeyStore ks = KeyStore.getInstance("JKS");
                ks.load(new FileInputStream(keyStoreDir+"cacerts.jks"), "changeit".toCharArray());
                PKIXParameters params = new PKIXParameters(ks);
                Set<TrustAnchor> trustAnchors = params.getTrustAnchors();
                // Set these as environment variables instead if possible...
                // Enable On-Line Certificate Status Protocol (OCSP) support
                //Security.setProperty("ocsp.enable", "false");
                //System.setProperty("com.sun.net.ssl.checkRevocation", "true");
                System.setProperty("com.sun.security.enableCRLDP", "true");
                verifyChain(certs.get(0), trustAnchors, certs, checkRevocation);
            } catch (GeneralSecurityException | IOException ex ) {
                Logger.getLogger(X509KeySelector.class.getName()).log(Level.SEVERE, null, ex);
                throw new KeySelectorException("Key could not be selected", ex);
            }
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

    static void verifyChain(X509Certificate cert, Set<TrustAnchor> trustAnchors, 
            List<X509Certificate> intermediateCerts, boolean checkRevocation) 
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathBuilderException {
            // Select the end-entity certificate
            X509CertSelector selector = new X509CertSelector(); 
	    selector.setCertificate(cert);
	    PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
            pkixParams.setRevocationEnabled(checkRevocation);

            // List the intermediate certificates
            CertStore intermediateCertStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(intermediateCerts));
            pkixParams.addCertStore(intermediateCertStore);

            // Build certificate chain, throws exception on fail
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            builder.build(pkixParams);
    }
    
    
    static boolean algEquals(String algURI, String algName) {
        return ((algName.equalsIgnoreCase("DSA")
                && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1))
                || (algName.equalsIgnoreCase("RSA")
                && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)));
    }
    
    public X509KeySelector(String keyStoreDir, boolean checkRevocation) {
        this.keyStoreDir=keyStoreDir;
        this.checkRevocation=checkRevocation;
    }
}
