package software.hsharp.api.helpers.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.glassfish.jersey.server.ContainerRequest;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.security.Key;

@Provider
@Priority(Priorities.AUTHENTICATION)
public class JwtAuthenticationFilter  implements ContainerRequestFilter {

    /**
     * HK2 Injection.
     */
    @Context
    Key key;

    @Inject
    javax.inject.Provider<UriInfo> uriInfo;

	public static final String AUTH_HEADER_KEY = "Authorization";
	public static final String AUTH_HEADER_VALUE_PREFIX = "Bearer "; // with trailing space to separate token

	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
        String method = requestContext.getMethod().toLowerCase();
		String path = ((ContainerRequest) requestContext).getPath(true).toLowerCase();

		if (("get".equals(method) && 
				("application.wadl".equals(path) || "application.wadl/xsd0.xsd".equals(path) || "status".equals(path) )
			)
				|| ("authentication".equals(path))) {
			// pass through the filter.
			requestContext.setSecurityContext(new SecurityContextAuthorizer(uriInfo, () -> "anonymous", new String[]{"anonymous"}));
			return;
		}

        String authorizationHeader = ((ContainerRequest) requestContext).getHeaderString(AUTH_HEADER_KEY);
        if (authorizationHeader == null) {
            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
        }

		String jwt = authorizationHeader.substring( AUTH_HEADER_VALUE_PREFIX.length() );
		if ( jwt != null && !jwt.isEmpty() ) {
			Jws<Claims> claims = JwtManager.parseToken(jwt);
			String login = (String) claims.getBody().get( "role" );
			requestContext.setSecurityContext(new SecurityContextAuthorizer(uriInfo, () -> login, new String[]{login}));
		}
	}

}
