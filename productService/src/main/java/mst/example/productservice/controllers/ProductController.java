package mst.example.productservice.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/products")
public class ProductController {

    @GetMapping("public")
    public String publicProducts(){

        return "Hello all! It's a public endpoint. Every user can reach me.";
    }


    @GetMapping("user")
    @PreAuthorize("hasRole('USER')")
    public String userProducts(){

        return "Hello dear User! This endpoint is available to USERs only.";
    }


    @GetMapping("admin")
    @PreAuthorize("hasRole('USER')")
    public String adminProducts(){

        return "Hello dear Admin! This endpoint is available to ADMINs only.";
    }
}
