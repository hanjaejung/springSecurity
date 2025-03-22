package com.example.spriingSecurity1.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NoticesController {

    @GetMapping("/notices") //의존성에 시큐리티만 추가해도 /welcome 접속시 로그인해야 한다
    public String getNotices(){

        return "Here are the notices details from the DB";
    }

}
