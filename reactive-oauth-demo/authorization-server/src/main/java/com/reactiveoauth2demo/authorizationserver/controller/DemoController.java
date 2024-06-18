package com.reactiveoauth2demo.authorizationserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

import java.util.List;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping
    public Flux<Integer> demo() {
        return Flux.fromIterable(List.of(1, 2, 3, 4, 5))
//                .delayElements(Duration.ofSeconds(1))
                ;
    }

}
