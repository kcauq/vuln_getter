package com.mywebapp.Springsecuritydemo.controller;

import com.mywebapp.Springsecuritydemo.JsonParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;


@RestController
public class VulnController {


    @Autowired
    private JsonParser jsonParser;

    @GetMapping("/vulnerabilities")
    public String vulnerabilities() throws IOException, InterruptedException {
        jsonParser.webCommunication();

        return "strona dziala";
    }
}
