
package com.quintor.testserver;

import com.quintor.testserver.x509.SignatureHelper;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;

/**
 * REST Documents resource
 *
 * @author rhegge
 */
@Path("/entities/{entityType}/documents")
public class DocumentsResource {

    @Context
    private UriInfo context;

    /**
     * Creates a new instance of DocumentsResource
     */
    public DocumentsResource() {
    }

    /**
     * Retrieves a list of documents for a given entity type
     * @return String - XML formatted list of documents
     */
    @GET
    @Produces("application/xml")
    public String getXmlDocumentList(@PathParam("entityType") String entityType) {
        return "<documents><document id='1'/><document id='2'/></documents>";
    }
    
    /**
     * Retrieves a document
     * @return String - XML formatted document
     */
    @GET
    @Path("{documentId}")
    @Produces("application/xml")
    public String getXmlDocument(@PathParam("entityType") String entityType, @PathParam("documentId") int documentId) {
        if(!entityType.equals("nl.qiy.example")) {
            throw new NotFoundException();
        }
        String xmlData="<document id='"+documentId+"'><someProperty id='1'>someValue</someProperty></document>";
        return SignatureHelper.signDocument(xmlData);
    }
}
