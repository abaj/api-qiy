
package com.quintor.testserver;

import com.quintor.testserver.x509.SignatureHelper;
import com.quintor.testserver.x509.SignatureVerificationException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;

/**
 * REST Web Service
 *
 * @author rhegge
 */
@Path("secure")
public class SecureResource {

    @Context
    private UriInfo context;

    /**
     * Creates a new instance of SecureResource
     */
    public SecureResource() {
    }

    /**
     * Retrieves representation of an instance of com.quintor.testserver.SecureResource
     * @return an instance of java.lang.String
     */
    @GET
    @Produces("application/xml")
    public String getXml() {
        String xmlData="<?xml version=\"1.0\" encoding=\"UTF-8\"?><xmldata>something</xmldata>";
        String signedDocumentString = SignatureHelper.signDocument(xmlData);
        String returnString = signedDocumentString;
        try {
            //Certificate validation fails if cert does not have any CRL extension. Dev certificate doesnt have this.
            SignatureHelper.parseSignature(signedDocumentString, false);
        } catch (SignatureVerificationException ex) {
            Logger.getLogger(SecureResource.class.getName()).log(Level.WARNING, null, ex);
            returnString="<error>Invalid Signature</error>";
        }
        return returnString;
    }

    /**
     * PUT method for updating or creating an instance of SecureResource
     * @param content representation for the resource
     * @return an HTTP response with content of the updated or created resource.
     */
    @PUT
    @Consumes("application/xml")
    public void putXml(String content) {
    }
}
