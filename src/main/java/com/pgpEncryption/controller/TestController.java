package com.pgpEncryption.controller;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.pgpEncryption.bean.RequestBean;
import com.pgpEncryption.service.PGPEncryptionService;

@RestController
public class TestController {

	public String fileLocation = "C:\\Temp\\";
	public String publicKeyFileName = "C:\\Users\\saudyadav\\OneDrive - Deloitte (O365D)\\Desktop Backup\\PGP\\Public.asc";
	public String privateKeyFileName = "C:\\Users\\saudyadav\\OneDrive - Deloitte (O365D)\\Desktop Backup\\PGP\\Private.asc";
	public String passphare = "123456789";
	boolean asciiArmored = false;
	boolean integrityCheck = false;

	@PostMapping(value = "/encrypt")
	@ResponseStatus(value = HttpStatus.OK)
	public ResponseEntity<Object> encrypt(@RequestBody RequestBean req) throws PGPException, NoSuchProviderException, IOException {

		ResponseEntity entity = null;
		try {
			boolean status = PGPEncryptionService.encrypt(publicKeyFileName, req.getInputFile(), req.getOutputFile(), asciiArmored, integrityCheck);

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
			
			boolean status = PGPEncryptionService.decrypt(req.getInputFile(), req.getOutputFile(), privateKeyFileName, passphare);
			
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
