package com.quintor.testserver.x509;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 *
 * @author rhegge
 */
public class SignatureHelper {
    private static String keyStoreDir="";
    private static final String PRIVATE_KEYSTORE="keystoretest.jks";
    private static final String PRIVATE_KEYSTORE_PASSWORD="changeit";
    private static final String SIGNING_KEY_ALIAS="localserv";
    
    protected static void setKeyStoreDir(String input) {
        keyStoreDir=input;
    }
    
    public static String signDocument(String input) {
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref;
        String output;
        try {
            ref = fac.newReference
                 ("", fac.newDigestMethod(DigestMethod.SHA1, null),
                         Collections.singletonList
                   (fac.newTransform
                    (Transform.ENVELOPED, (TransformParameterSpec) null)),
                         null, null);
            // Create the SignedInfo.
            SignedInfo si = fac.newSignedInfo
                 (fac.newCanonicalizationMethod
                  (CanonicalizationMethod.INCLUSIVE,
                          (C14NMethodParameterSpec) null),
                         fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                         Collections.singletonList(ref));
        
            // Load the KeyStore and get the signing key and certificate.
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keyStoreDir+PRIVATE_KEYSTORE), PRIVATE_KEYSTORE_PASSWORD.toCharArray());
            KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry
                    (SIGNING_KEY_ALIAS, new KeyStore.PasswordProtection(PRIVATE_KEYSTORE_PASSWORD.toCharArray()));
            X509Certificate[] certs = (X509Certificate[]) keyEntry.getCertificateChain();

            // Create the KeyInfo containing the X509Data.
            KeyInfoFactory kif = fac.getKeyInfoFactory();
            List x509Content = new ArrayList();
            for(X509Certificate cert : certs) {
                x509Content.add(cert);
            }
            X509Data xd = kif.newX509Data(x509Content);
            KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

            // Instantiate the document to be signed.
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(input)));

            // Create a DOMSignContext and specify the RSA PrivateKey and
            // location of the resulting XMLSignature's parent element.
            DOMSignContext dsc = new DOMSignContext
                (keyEntry.getPrivateKey(), doc.getDocumentElement());

            // Create the XMLSignature, but don't sign it yet.
            XMLSignature signature = fac.newXMLSignature(si, ki);

            // Marshal, generate, and sign the enveloped signature.
            signature.sign(dsc);
            
            //Output signed document
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            output = writer.getBuffer().toString().replaceAll("\n|\r", "");
            
        } catch (KeyStoreException | ParserConfigurationException | TransformerException | SAXException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException | MarshalException | XMLSignatureException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(SignatureHelper.class.getName()).log(Level.SEVERE, null, ex);
            output="<warning>Oh no it broke!</warning>";
        }
        return output;
    }
    
    public static String parseSignature(String input, boolean checkRevocation) throws SignatureVerificationException {
        String parsedMessage="";
        //Now to parse the string
        Boolean coreValidity=false;
        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc;
        try {
            doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(input)));

            // Find Signature element.
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new SignatureVerificationException("Cannot find Signature element");
            }
            // Create a DOMValidateContext and specify a KeySelector and document context.
            DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(keyStoreDir, checkRevocation), nl.item(0));
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            
            valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);
            // Unmarshal the XMLSignature.
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);

            // Validate the XMLSignature.
            coreValidity = signature.validate(valContext);

            // Check core validation status.
            if (!coreValidity) {
                throw new SignatureVerificationException("Signature validation failed");
            }
            
            StringBuilder sb = new StringBuilder();
            Iterator i = signature.getSignedInfo().getReferences().iterator();
            for (int j=0; i.hasNext(); j++) {
                try (InputStream is = ((Reference) i.next()).getDigestInputStream(); 
                        BufferedReader in = new BufferedReader(new InputStreamReader(is))) {
                    String inputLine;
                    while ((inputLine = in.readLine()) != null) {
                        sb.append(inputLine);
                    }
                }
            }
            parsedMessage=sb.toString();
        } catch (SAXException | IOException | ParserConfigurationException | MarshalException | XMLSignatureException ex) {
            Logger.getLogger(SignatureHelper.class.getName()).log(Level.SEVERE, null, ex);
            throw new SignatureVerificationException("Signature could not be parsed", ex);
        }
        return parsedMessage;
    }
}