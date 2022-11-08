package mst.example.authserver.exceptionHandlers;


import mst.example.authserver.dto.ErrorResponseModel;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;


// This class handles error and return appropriate response to client
@ControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)
public class GeneralExceptionHelper {

    // handling other Exception
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseModel> handleException(Exception ex, WebRequest request) {

        ErrorResponseModel errorResponseModel = new ErrorResponseModel();
        errorResponseModel.setMessage("Internal Error");
        errorResponseModel.setDescription(ex.getMessage());

        // send response with 500 status code
        return new ResponseEntity<>(errorResponseModel, HttpStatus.INTERNAL_SERVER_ERROR);

    }




}