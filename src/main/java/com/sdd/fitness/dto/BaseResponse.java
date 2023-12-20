package com.sdd.fitness.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.sdd.fitness.constant.Message;
import lombok.Builder;
import lombok.Data;
import org.springframework.http.HttpStatusCode;

@Data
public class BaseResponse<T> {

    private Integer status;

    private String message;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private T payload;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String additionalInfo;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Object errors;

    @Builder
    public BaseResponse(HttpStatusCode status, Message message, T payload, String additionalInfo, Object errors) {
        this.status = status.value();
        this.message = message.value();
        this.additionalInfo = additionalInfo;
        this.payload = payload;
        this.errors = errors;
    }

}