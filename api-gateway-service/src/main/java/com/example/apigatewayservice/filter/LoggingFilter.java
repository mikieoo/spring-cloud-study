package com.example.apigatewayservice.filter;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class LoggingFilter extends AbstractGatewayFilterFactory<LoggingFilter.Config> {
    public LoggingFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        // Custom Pre Filter
//        return (exchange, chain) -> {
//            ServerHttpRequest request = exchange.getRequest();
//            ServerHttpResponse response = exchange.getResponse();
//
//            log.info("Global Filter baseMessage: -> {}", config.getBaseMessage());
//
//            if (config.isPreLogger()) {
//                log.info("Global Filter Start: request id -> {}", request.getId());
//            }
//
//            //Custom Post Filter
//            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
//                if (config.isPostLogger()) {
//                    log.info("Global Filter End: response id -> {}", response.getStatusCode());
//                }
//            }));
//        };
        GatewayFilter filter = new OrderedGatewayFilter((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            log.info("Logging Filter baseMessage: -> {}", config.getBaseMessage());

            if (config.isPreLogger()) {
                log.info("Logging PRE Filter: request id -> {}", request.getId());
            }

            //Custom Post Filter
            return chain.filter(exchange).then(Mono.fromRunnable(() -> {
                if (config.isPostLogger()) {
                    log.info("Logging POST Filter: response id -> {}", response.getStatusCode());
                }
            }));
        }, Ordered.LOWEST_PRECEDENCE); // Ordered.HIGHEST_PRECEDENCE : 필터의 우선순위를 정함

        return filter;
    }

    @Data
    public static class Config {
        private String baseMessage;
        private boolean preLogger;
        private boolean postLogger;
    }
}
