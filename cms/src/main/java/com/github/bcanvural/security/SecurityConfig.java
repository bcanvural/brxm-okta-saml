package com.github.bcanvural.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import static org.springframework.security.extensions.saml2.config.SAMLConfigurer.saml;

@EnableWebSecurity
@Configuration
@PropertySource("classpath:application.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Value("${security.saml2.metadata-url}")
    String metadataUrl;

    @Value("${server.ssl.key-alias}")
    String keyAlias;

    @Value("${server.ssl.key-store-password}")
    String password;

    @Value("${server.port}")
    String port;

    @Value("${server.ssl.key-store}")
    String keyStoreFilePath;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/saml*", "/*.gif", "/*.jpg", "/*.jpeg", "/*.png", "/*.jsp", "/*.js", "/*.css", "/console*").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterAfter(new LoginSuccessFilter(), FilterSecurityInterceptor.class)
                .apply(saml())
                .serviceProvider()
                .keyStore()
                .storeFilePath(this.keyStoreFilePath)
                .password(this.password)
                .keyname(this.keyAlias)
                .keyPassword(this.password)
                .and()
                .protocol("http")
                .hostname(String.format("%s:%s", "localhost", this.port))
                .basePath("/cms")
                .and()
                .identityProvider()
                .metadataFilePath(this.metadataUrl);
    }
}
