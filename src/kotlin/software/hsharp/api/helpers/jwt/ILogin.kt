package software.hsharp.api.helpers.jwt

interface ILogin {
    val loginName : String
    val password : String
}

interface ILoginResponse {
    val logged : Boolean
    val token : String?
}

interface ILoginService {
    val uniqueKey : String
    fun login( login : ILogin ) : ILoginResponse
}

interface ILoginServiceRegister {
    fun registerLoginService( service : ILoginService )
    val loginServices : Array<ILoginService>
}
