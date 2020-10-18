package br.com.alura.forum.config.validacao;

import lombok.Data;

@Data
public class ErroDeFormularioDto {

	private String campo;
	private String erro;
	
	public ErroDeFormularioDto(String campo, String erro) {
		super();
		this.campo = campo;
		this.erro = erro;
	}
	
}
