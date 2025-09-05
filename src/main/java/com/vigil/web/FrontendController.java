package com.vigil.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class FrontendController {

    @RequestMapping(value = {"/", "/dashboard"})
    public String index() {
        return "forward:/index.html";
    }
}
