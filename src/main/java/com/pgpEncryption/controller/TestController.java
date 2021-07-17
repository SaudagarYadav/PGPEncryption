package com.pgpEncryption.controller;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.pgpEncryption.service.PGPEncryptionService;

@RestController
public class TestController {

	public String fileLocation = "C:\\Temp\\";
	public String publicKeyFileName = "C:\\Temp\\Public.asc";
	public String privateKeyFileName = "C:\\Temp\\Private.asc";
	public String passphare = "123456789";
	boolean asciiArmored = false;
	boolean integrityCheck = false;

	@GetMapping(value = "/encrypt")
	@ResponseStatus(value = HttpStatus.OK)
	public ResponseEntity<Object> encryptMerthod() throws PGPException, NoSuchProviderException, IOException {

		ResponseEntity entity = null;
		try {
			String inputFile = fileLocation + "test.xml";
			String outputFile = fileLocation + "enTest.xml";
			PGPEncryptionService.encrypt(publicKeyFileName, inputFile, outputFile, asciiArmored, integrityCheck);
			Map<String, String> resposne = new HashMap<String, String>();
			resposne.put("Input file", "test.xml");
			resposne.put("Output file(Encrypted file)", "enTest.xml");
			entity = new ResponseEntity<>(resposne, HttpStatus.OK);
			return entity;
		} catch (Exception e) {
			entity = new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
			e.printStackTrace();
			return entity;
		}
	}

	@GetMapping(value = "/decrypt")
	public ResponseEntity<Object> decrypt() throws PGPException, NoSuchProviderException, IOException {
		ResponseEntity entity = null;
		try {
			String inputFile = fileLocation + "enTest.xml";
			String outputFile = fileLocation + "deTest.xml";
			
			PGPEncryptionService.decrypt(inputFile, outputFile, privateKeyFileName, passphare);
			
			// reponse
			Map<String, String> resposne = new HashMap<String, String>();
			resposne.put("Input file (Encrypted)", "enTest.xml");
			resposne.put("Output file(Decrypted file)", "deTest.xml");
			entity = new ResponseEntity<>(resposne, HttpStatus.OK);
			return entity;
		} catch (Exception e) {
			entity = new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
			e.printStackTrace();
			return entity;
		}
	}

}
