
package com.quintor.testserver;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.Produces;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

/**
 * REST entities resource
 *
 * @author rhegge
 */
@Path("entities")
public class EntitiesResource {

    @Context
    private UriInfo context;

    /**
     * Creates a new instance of EntitiesResource
     */
    public EntitiesResource() {
    }

    /**
     * Retrieves a list of available entity types
     * @return String - XML formatted list of available entities
     */
    @GET
    @Produces("application/xml")
    public String getXml() {
        return "<entities><entity type=\"nl.qiy.example\"/></entities>";
    }
}
