package mst.example.authserver.exceptionHandlers;

import com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import mst.example.authserver.dto.ErrorResponseModel;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;


// This class handles error and return appropriate response to client
@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AuthenticationExceptionHelper {





    // handling AuthenticationException
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponseModel> handleAuthenticationException(AuthenticationException ex, WebRequest request) {


        ErrorResponseModel errorResponseModel = new ErrorResponseModel();
        errorResponseModel.setMessage("Authentication Error");
        errorResponseModel.setDescription("Credential not match");

        // send response with 401 status code
        return new ResponseEntity(errorResponseModel, HttpStatus.UNAUTHORIZED);


    }


    // handling AccessDeniedException
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponseModel> handleIAccessDeniedException(AccessDeniedException ex, WebRequest request) {


        ErrorResponseModel errorResponseModel = new ErrorResponseModel();
        errorResponseModel.setMessage("Access Denied");
        errorResponseModel.setDescription(ex.getMessage());

        // send response with 401 status code
        return new ResponseEntity(errorResponseModel, HttpStatus.FORBIDDEN);


    }

    // handling MethodArgumentNotValidException
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseModel> handleIInvalidTypeIdException(MethodArgumentNotValidException ex, WebRequest request) {


        ErrorResponseModel errorResponseModel = new ErrorResponseModel();
        errorResponseModel.setMessage("Input Parameter Error");
        errorResponseModel.setDescription("Given parameter(s) are not valid.");

        // send response with 400 status code
        return new ResponseEntity(errorResponseModel, HttpStatus.BAD_REQUEST);


    }






}