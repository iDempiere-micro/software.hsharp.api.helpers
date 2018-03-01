package software.hsharp.api.helpers.jwt

import java.security.Principal
import javax.security.auth.Subject
import javax.ws.rs.core.SecurityContext
import javax.ws.rs.core.UriInfo

interface IUserLoginModel

class SecurityContextAuthorizer(
        private val uriInfo: javax.inject.Provider<UriInfo>,
        private val userName: String,
        private val roles: Array<String>,
        val userLoginModel : IUserLoginModel
) : SecurityContext {

    private var principal: Principal? = null

    init {
        if (principal == null) {
            principal = object : Principal {
                override fun getName(): String {
                    return userName
                }

                override fun implies(subject: Subject?): Boolean {
                    return ( subject != null && subject.principals.contains(principal))
                }
            }
        }
    }

    override fun getUserPrincipal(): Principal? {
        return principal
    }

    override fun isUserInRole(role: String?): Boolean {
        return this.roles.contains(role ?: "")
    }

    override fun isSecure(): Boolean {
        return "https" == uriInfo.get().requestUri.scheme
    }

    override fun getAuthenticationScheme(): String {
        return SecurityContext.DIGEST_AUTH
    }
}