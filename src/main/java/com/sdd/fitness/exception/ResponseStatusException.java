package com.sdd.fitness.exception;

import com.sdd.fitness.constant.Message;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

@Getter
public class ResponseStatusException extends org.springframework.web.server.ResponseStatusException {

    private final Message EMessage;

    public ResponseStatusException(HttpStatus status, Message message) {
        super(status, status.name());
        this.EMessage = message;
    }

}
