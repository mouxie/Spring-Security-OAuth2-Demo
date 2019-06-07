package com.yanmouxie.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;
	
    @Override
	public void configure(ClientDetailsServiceConfigurer clients)
			throws Exception {
    	
		clients.inMemory()
				.withClient("myclient")
				.secret("$2a$10$tEFtDKpFh6eAr07inuDYVOtVAArj1NK3ulnj8KuUp7rHjrjYPzzD.") // = mysecret
				.authorizedGrantTypes("authorization_code","client_credentials", "refresh_token")
				.scopes("all","resource-server-read", "resource-server-write")
				.redirectUris("http://127.0.0.1:8090/login/oauth2/code/callback")
				.accessTokenValiditySeconds(300)
				.resourceIds("oauth2-server")

				.and()
				.withClient("ResourceServer")
				.secret("$2a$10$0rrAX0SkBmnQhkLjPmgJkuivkU.D5iUisgyeMFk8k0MQCLwHXw5kC") // = ResourceServerSecret
				.authorizedGrantTypes("authorization_code", "implicit",
						"password", "client_credentials", "refresh_token")
				.authorities("ROLE_TRUSTED_CLIENT")
				.resourceIds("oauth2-server");
	}
    
	@Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		
		// Add PasswordEncoder
		security.passwordEncoder(new BCryptPasswordEncoder());
		
		// Allow uri http://localhost:<port>/oauth/check_token for Client with trusted Role
		security.tokenKeyAccess(
				"isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
				.checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        super.configure(endpoints);
    }
    
    public static void main(String[] args) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        System.out.println(bCryptPasswordEncoder.encode("mysecret"));
        System.out.println(bCryptPasswordEncoder.encode("ResourceServerSecret"));
    }
}