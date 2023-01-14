package mst.example.authserver.controllers;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mst.example.authserver.dto.AuthenticationRequest;
import mst.example.authserver.dto.AuthenticationResponse;
import mst.example.authserver.dto.RefreshTokenRequest;
import mst.example.authserver.security.jwt.JwtTokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import javax.validation.Valid;



@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {


    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@Valid @RequestBody AuthenticationRequest authRequest) throws AuthenticationException {


        Authentication authentication = this.authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                                                                        authRequest.getUsername(),
                                                                        authRequest.getPassword()
                                                                      ));
       log.info(" Authentication process ");
       log.info(" Username : " + authRequest.getUsername());
       log.info(" Password : " + authRequest.getPassword());

        String accessToken = this.tokenProvider.createToken(authentication, "access");
        String refreshToken = this.tokenProvider.createToken(authentication, "refresh");

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        AuthenticationResponse authenticationResponse = new AuthenticationResponse(accessToken,refreshToken);
        return new ResponseEntity<>(authenticationResponse, httpHeaders, HttpStatus.OK);


    }



    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {

            if(!tokenProvider.validateToken(refreshTokenRequest.getRefreshToken()))
                throw new AccessDeniedException("Access denied");

        log.info(" Refresh process ");
        log.info(" Username : " + tokenProvider.getAuthentication(refreshTokenRequest.getRefreshToken()).getPrincipal());
        String accessToken = this.tokenProvider.createToken(refreshTokenRequest.getRefreshToken(), "access");
        String refreshToken = this.tokenProvider.createToken(refreshTokenRequest.getRefreshToken(), "refresh");

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        AuthenticationResponse authenticationResponse = new AuthenticationResponse(accessToken,refreshToken);
        return new ResponseEntity<>(authenticationResponse, httpHeaders, HttpStatus.OK);

    }

    }
