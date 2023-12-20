package com.sdd.fitness.exception;

import com.sdd.fitness.constant.Message;
import com.sdd.fitness.dto.BaseResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request
    ) {
        List<Map<String, String>> errors = new ArrayList<>();

        ex.getBindingResult()
                .getAllErrors()
                .forEach((error) -> {
                    String fieldName = ((FieldError) error).getField();
                    String message = error.getDefaultMessage();

                    Map<String, String> errorObject = Map.of(
                            "field", fieldName,
                            "message", Objects.requireNonNullElse(message, "")
                    );

                    errors.add(errorObject);
                });

        BaseResponse<Object> response = BaseResponse.builder()
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .message(Message.VALIDATION_ERROR)
                .errors(errors)
                .build();


        return ResponseEntity
                .status(response.getStatus())
                .body(response);
    }

}
