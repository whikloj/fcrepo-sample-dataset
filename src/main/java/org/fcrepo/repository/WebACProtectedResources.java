package org.fcrepo.repository;

import static java.lang.Integer.MAX_VALUE;
import static org.fcrepo.repository.FedoraDatasetImport.setAuth;
import static org.slf4j.LoggerFactory.getLogger;
import static javax.ws.rs.core.Response.Status.NO_CONTENT;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;

/**
 * Creates Fedora Resources that will be protected by the WebAC acl rules.
 *
 * @author whikloj
 * @since 2015-10-01
 */
public class WebACProtectedResources {

    private static final Logger LOGGER = getLogger(WebACProtectedResources.class);

    final private String baseUrl;

    final private String username;

    final private String password;

    final private HttpClient client;

    final static private List<String> resources = Arrays.asList("webacl_box1", "box/bag/collection", "dark/archive",
            "dark/archive/sunshine", "public_collection", "mixedCollection");

    final static private Map<String, String> acl_links;

    static {
        acl_links = new HashMap<String, String>();
        acl_links.put("webacl_box1", "acls/01/acl");
        acl_links.put("box/bag/collection", "acls/02/acl");
        acl_links.put("dark/archive", "acls/03/acl");
        acl_links.put("dark/archive/sunshine", "acls/03/acl");
        acl_links.put("public_collection", "acls/04/acl");
        acl_links.put("mixedCollection", "acls/05/acl");
    }

    public WebACProtectedResources(final String baseUrl, final String username, final String password) {
        this.baseUrl = baseUrl;
        this.username = username;
        this.password = password;
        this.client = HttpClientBuilder.create().setMaxConnPerRoute(MAX_VALUE)
                .setMaxConnTotal(MAX_VALUE).build();

    }

    public void loadResources() throws UnsupportedEncodingException {
        for (final String resourceUri : acl_links.keySet()) {
            putResourceToProtect(baseUrl + resourceUri,
                    "<> a <http://www.w3.org/ns/ldp#BasicContainer> .");
        }
    }

    public void linkResources() throws UnsupportedEncodingException {
        for (final Entry<String, String> entry : acl_links.entrySet()) {
            linkResourceToProtect(baseUrl + entry.getKey(), baseUrl + entry.getValue());
        }
    }

    public void linkResourceToProtect(final String resource, final String acl) throws UnsupportedEncodingException {
        LOGGER.info("Link resource {} to acl {}", resource, acl);
        final HttpPatch request = new HttpPatch(resource);
        if (username != null && password != null) {
            setAuth(request, username, password);
        }

        request.setEntity(new StringEntity(
                "INSERT { <> <http://www.w3.org/ns/auth/acl#accessControl> <" + acl +
                        "> . } WHERE {}"));
        request.addHeader("Content-type", "application/sparql-update");
        try {
            final HttpResponse res = client.execute(request);
            if (res.getStatusLine().getStatusCode() != NO_CONTENT.getStatusCode()) {
                LOGGER.warn("Error patching {}, {}", resource, res.getStatusLine().toString());
            }
        } catch (final Exception e) {
            LOGGER.warn("Failed to add ACL {} to resource {} ", acl, resource);
            e.printStackTrace();
        }
    }

    public void putResourceToProtect(final String requestUri, final String body)
            throws UnsupportedEncodingException {
        LOGGER.info("Adding resource {} to repository", requestUri);
        final HttpPut request = new HttpPut(requestUri);
        if (username != null && password != null) {
            setAuth(request, username, password);
        }
        request.setEntity(new StringEntity(body));
        request.addHeader("Content-type", "text/turtle");
        try {
            client.execute(request);
        } catch (final Exception e) {
            LOGGER.warn("Failed to PUT " + requestUri);
            e.printStackTrace();
        }
    }
}
