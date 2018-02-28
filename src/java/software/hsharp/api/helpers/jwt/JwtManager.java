package software.hsharp.api.helpers.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Date;

public class JwtManager {

    private static final String CLAIM_ROLE = "role";

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;
    private static final TemporalAmount TOKEN_VALIDITY = Duration.ofHours( 4L );
    private static final SecretKey SECRET_KEY = generateKey();

    private static SecureRandom DEFAULT_SECURE_RANDOM;
    
    private static JwtManager instance;

    protected JwtManager() {
        instance = this;
    }    
    protected static JwtManager getInstance() {
        if ( instance == null ) {
            instance = new JwtManager();
        }
        return instance;
    }    

    private static SecretKey generateKey() {
        byte[] bytes = new byte[32];
        if ( DEFAULT_SECURE_RANDOM == null ) {
            DEFAULT_SECURE_RANDOM = new SecureRandom();
            DEFAULT_SECURE_RANDOM.nextBytes(new byte[64]);
        }
        DEFAULT_SECURE_RANDOM.nextBytes(bytes);

        return new SecretKeySpec(bytes, SIGNATURE_ALGORITHM.getJcaName());
    }

    /**
     * Builds a JWT with the given subject and role and returns it as a JWS signed compact String.
     */
    public static String createToken( final String subject, final String role ) {
        return getInstance().doCreateToken( subject, role );
    }

    private String doCreateToken( final String subject, final String role ) {
        final Instant now = Instant.now();
        final Date expiryDate = Date.from( now.plus( TOKEN_VALIDITY ) );
        return Jwts.builder()
                   .setSubject( subject )
                   .claim( CLAIM_ROLE, role )
                   .setExpiration( expiryDate )
                   .setIssuedAt( Date.from( now ) )
                   .signWith( SIGNATURE_ALGORITHM, SECRET_KEY )
                   .compact();
    }

    /**
     * Parses the given JWS signed compact JWT, returning the claims.
     * If this method returns without throwing an exception, the token can be trusted.
     */
    public static Jws<Claims> parseToken( final String compactToken ) {
        return getInstance().doParseToken( compactToken );
    }

    private Jws<Claims> doParseToken( final String compactToken )
            throws ExpiredJwtException,
                   UnsupportedJwtException,
                   MalformedJwtException,
                   SignatureException,
                   IllegalArgumentException {
        return Jwts.parser()
                   .setSigningKey( SECRET_KEY )
                   .parseClaimsJws( compactToken );
    }
}