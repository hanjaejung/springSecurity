package com.example.spriingSecurity1.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CsrfCookieFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        //Render the token value to a cookie by causing the deferred token to by loaded
        csrfToken.getToken();
        //해당 필터에서 필터 체인의 다음 필터로 요청 전달 확인
        filterChain.doFilter(request,response);
        //이제 스프링 시큐리티에게 이 필터를 알려야 한다
    }
}
