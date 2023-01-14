package mst.example.productservice.jwt;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Data
public class JwtProperties {

    @Value("${jwt.secret}")
    private String secretKey = "";

    // validity in milliseconds
    private long accessTokenValidityInMs = 3600000; // 1h

    private long refreshTokenValidityInMs = 3600000 * 5; // 1h

}
