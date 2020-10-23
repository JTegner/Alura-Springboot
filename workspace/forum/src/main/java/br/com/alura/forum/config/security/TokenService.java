package br.com.alura.forum.config.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class TokenService {
	
	@Value("${forum.jwt.expiration}")
	private String expiration;

	@Value("${forum.jwt.secret}")
	private String secret;

	public String gerarToken(Authentication authentication) {
		Usuario logado = (Usuario) authentication.getPrincipal(); //devolve object por isso o cast
		Date hoje = new Date();
		Date dataExpiracao = new Date(hoje.getTime() + Long.parseLong(expiration));

		return Jwts.builder()
				.setIssuer("API do fórum da Alura") //quem gerou o token
				.setSubject(logado.getId().toString()) //quem é o usuário a quem esse token pertence
				.setIssuedAt(hoje) //data de geracao do token
				.setExpiration(dataExpiracao) //em producao tempo pequeno 15 ou 30 minutos
				.signWith(SignatureAlgorithm.HS256, secret) //algoritmo que gera a senha
				.compact();
	}

	public boolean isTokenValido(String token) {
		try {
			Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	public Long getIdUsuario(String token) {
		Claims claims = Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token).getBody();
		//System.out.println("claims: " + claims);
		//System.out.println("claims.getSubject(): " + claims.getSubject());
		return Long.parseLong(claims.getSubject());
	}
	
}
