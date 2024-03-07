package com.example.SpringJWT.controller;

import com.example.SpringJWT.dto.JoinDto;
import com.example.SpringJWT.service.JoinService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JoinController {

    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinProcess(@RequestBody JoinDto joinDto){
        joinService.join(joinDto);

        return "ok";
    }
}
