package software.hsharp.api.helpers.jwt

import org.glassfish.jersey.server.ContainerRequest
import java.io.IOException
import java.security.Key
import javax.annotation.Priority
import javax.inject.Inject
import javax.ws.rs.Priorities
import javax.ws.rs.WebApplicationException
import javax.ws.rs.container.ContainerRequestContext
import javax.ws.rs.container.ContainerRequestFilter
import javax.ws.rs.core.Context
import javax.ws.rs.core.Response
import javax.ws.rs.core.UriInfo
import javax.ws.rs.ext.Provider

@Provider
@Priority(Priorities.AUTHENTICATION)
open abstract class JwtAuthenticationFilter : ContainerRequestFilter {

    /**
     * HK2 Injection.
     */
    @Context
    internal var key: Key? = null

    @Inject
    internal var uriInfo: javax.inject.Provider<UriInfo>? = null

    protected abstract fun decodeUserLoginModel(requestContext : ContainerRequestContext, userLoginModel:String) : IUserLoginModel;
    protected abstract fun decodeRoles(roleModel:String) : Array<String>;

    @Throws(IOException::class)
    override fun filter(requestContext: ContainerRequestContext) {
        val method = requestContext.method.toLowerCase()
        val path = (requestContext as ContainerRequest).getPath(true).toLowerCase()

        val queryParameters = requestContext.uriInfo.queryParameters

        if ("get" == method && ("application.wadl" == path || "application.wadl/xsd0.xsd" == path || "status" == path) || "authentication" == path) {
            // pass through the filter.
            requestContext.setSecurityContext(NoLoginSecurityContextAuthorizer(uriInfo!!))
            return
        }

        val authorizationHeader = requestContext.getHeaderString(AUTH_HEADER_KEY)
        if (authorizationHeader == null && (queryParameters == null || !queryParameters.containsKey("token"))) {
            throw WebApplicationException(Response.Status.UNAUTHORIZED)
        }

        val jwt = authorizationHeader?.substring(AUTH_HEADER_VALUE_PREFIX.length) ?: queryParameters!!.getFirst("token")
        if (jwt != null && !jwt.isEmpty()) {
            val claims = JwtManager.parseToken(jwt)
            val userLogin = claims.body.subject as String
            val role = claims.body[JwtManager.CLAIM_ROLE] as String
            val userLoginModel = claims.body[JwtManager.CLAIM_LOGINMODEL] as String
            requestContext.setSecurityContext(
                    SecurityContextAuthorizer(
                            uriInfo!!, userLogin, decodeRoles(role), decodeUserLoginModel(requestContext, userLoginModel)
                    )
            )
            return
        }
        throw WebApplicationException(Response.Status.UNAUTHORIZED)
    }

    companion object {

        val AUTH_HEADER_KEY = "Authorization"
        val AUTH_HEADER_VALUE_PREFIX = "Bearer " // with trailing space to separate token
    }

}
