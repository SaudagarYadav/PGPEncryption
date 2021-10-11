package com.pgpEncryption.controller;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.pgpEncryption.bean.RequestBean;
import com.pgpEncryption.service.PGPEncryptionService;

@RestController
public class Controller {

	boolean asciiArmored = false;
	boolean integrityCheck = false;

	@PostMapping(value = "/encrypt")
	@ResponseStatus(value = HttpStatus.OK)
	public ResponseEntity<Object> encrypt(@RequestBody RequestBean req) throws PGPException, NoSuchProviderException, IOException {

		ResponseEntity entity = null;
		try {
			boolean status = PGPEncryptionService.encrypt(req.getPublicKey(), req.getInputFile(), req.getOutputFile(), asciiArmored, integrityCheck);

			if (status) {
				Map<String, String> resposne = new HashMap<String, String>();
				resposne.put("Input file", req.getInputFile());
				resposne.put("Output file(Encrypted file)", req.getOutputFile());
				entity = new ResponseEntity<>(resposne, HttpStatus.OK);	
			} else {
				entity = new ResponseEntity<>(HttpStatus.BAD_REQUEST);
			}
			return entity;
		} catch (Exception e) {
			entity = new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
			e.printStackTrace();
			return entity;
		}
	}

	@PostMapping(value = "/decrypt")
	public ResponseEntity<Object> decrypt(@RequestBody RequestBean req) throws PGPException, NoSuchProviderException, IOException {
		ResponseEntity entity = null;
		try {
			
			boolean status = PGPEncryptionService.decrypt(req.getInputFile(), req.getOutputFile(), req.getPrivateKey(), req.getPassphrase());
			
			// reponse
			if (status) {
				Map<String, String> resposne = new HashMap<String, String>();
				resposne.put("Input file (Encrypted)", req.getInputFile());
				resposne.put("Output file(Decrypted file)", req.getOutputFile());
				entity = new ResponseEntity<>(resposne, HttpStatus.OK);				
			} else {
				entity = new ResponseEntity<>(HttpStatus.BAD_REQUEST);
			}
			return entity;
		} catch (Exception e) {
			entity = new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
			e.printStackTrace();
			return entity;
		}
	}

}
