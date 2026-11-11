package com.futbolix.customers.adapter.in.web;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/** ErrorResponse of _shared.yaml. */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ErrorResponse(String error, String message, List<Detail> details, String traceId) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Detail(String field, String message) {
    }
}
