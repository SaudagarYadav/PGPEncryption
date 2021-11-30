package com.pgpEncryption.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.PGPException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.SftpException;
import com.pgpEncryption.bean.RequestBean;
import com.pgpEncryption.bean.SftpRequest;
import com.pgpEncryption.service.PGPEncryptionService;
import com.pgpEncryption.service.PGPFileContentEncryption;
import com.pgpEncryption.service.SFTPService;

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

	@PostMapping(value = "/encryptContent")
	@ResponseStatus(value = HttpStatus.OK)
	public ResponseEntity<Object> encryptContent(@RequestBody RequestBean req) throws PGPException, NoSuchProviderException, IOException {
		
		ResponseEntity entity = null;
		try {
			
			PGPFileContentEncryption pgp = new PGPFileContentEncryption();
			pgp.encryptFile(req.getPublicKey(), req.getOutputFile(), req.getInputFile());
			return entity;
		} catch (Exception e) {
			entity = new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
			e.printStackTrace();
			return entity;
		}
	}
	
	@PostMapping(value = "/decryptContent")
	public ResponseEntity<Object> decryptContent(@RequestBody RequestBean req) throws PGPException, NoSuchProviderException, IOException {
		ResponseEntity entity = null;
		try {

			PGPFileContentEncryption pgp = new PGPFileContentEncryption();
			InputStream contentInpuStream = pgp.decryptAndVerify(req.getInputFile(), req.getPrivateKey(), req.getPassphrase());
			createFile(req.getOutputFile(),contentInpuStream);
			return entity;
		} catch (Exception e) {
			entity = new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
			e.printStackTrace();
			return entity;
		}
	}
	
	@GetMapping(value = "createFolder")
	public StringBuilder createFolderGet(@RequestParam(required = true) String hostUrl,
			@RequestParam(required = true) int port,
			@RequestParam(required = true) String userName,
			@RequestParam(required = true) String password,
			@RequestParam(required = true) String location,
			@RequestParam(required = true) String privateKeyLocation) throws JSchException, SftpException {
	
		try {
			
			SftpRequest req = new SftpRequest(hostUrl, port, userName, password, privateKeyLocation, privateKeyLocation);
			
			return folderCreationOperation(req);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	@PostMapping(value = "create")
	public StringBuilder createFolderPost(@RequestBody SftpRequest req) throws JSchException, SftpException {
		
		try {
			return folderCreationOperation(req);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	private StringBuilder folderCreationOperation(SftpRequest req)
			throws JSchException, FileNotFoundException, IOException, SftpException {
		StringBuilder response = getHeader();
		setfolder(response, "Folder Created");
		
		ChannelSftp sftpConnection = SFTPService.getSftpConnection(req);
		
		
		File file = new File(req.getLocation());
		
		BufferedReader br = new BufferedReader(new FileReader(file));
		String st;
		System.out.println("Folder creation started");
		while ((st = br.readLine()) != null) {
			System.out.println(st);
			String[] folders = st.split( "/" );
			for ( String folder : folders ) {
				if ( folder.length() > 0 ) {
					try {
						sftpConnection.cd(folder);
					}
					catch ( SftpException e ) {
						sftpConnection.mkdir(folder);
						sftpConnection.cd(folder);
					}
				}
			}
			sftpConnection.cd("/");
			setfolder(response, st);
		}
		System.out.println("All Folder created");
		getFooter(response);
		SFTPService.disconnectChannelSftp(sftpConnection);
		return response;
	}

	private StringBuilder getFooter(StringBuilder response) {
		return response.append("\r\n"
				+ "</table>\r\n"
				+ "\r\n"
				+ "</body>\r\n"
				+ "</html>");
	}
	
	private StringBuilder setfolder(StringBuilder response, String folder) {
		response = response.append("<tr>\r\n"
				+ "    <td>"+folder+"</td>\r\n"
				+ "  </tr>");
		return response;
	}

	private StringBuilder getHeader() {
		StringBuilder str= new StringBuilder("<!DOCTYPE html>\r\n"
				+ "<html>\r\n"
				+ "<head>\r\n"
				+ "<style>\r\n"
				+ "table {\r\n"
				+ "  font-family: arial, sans-serif;\r\n"
				+ "  border-collapse: collapse;\r\n"
				+ "}\r\n"
				+ "\r\n"
				+ "td, th {\r\n"
				+ "  border: 1px solid #dddddd;\r\n"
				+ "  text-align: left;\r\n"
				+ "  padding: 8px;\r\n"
				+ "}\r\n"
				+ "\r\n"
				+ "tr:nth-child(odd) {\r\n"
				+ "  background-color: #dddddd;\r\n"
				+ "}\r\n"
				+ "</style>\r\n"
				+ "</head>\r\n"
				+ "<body>\r\n"
				+ "\r\n"
				+ "<h2>File created Successfully</h2>\r\n"
				+"<table>");
		
		return str;
	}

	public void createFile(String filePath, InputStream initialStream) throws IOException {
		File targetFile = new File(filePath);
		OutputStream outStream = new FileOutputStream(targetFile);

		byte[] buffer = new byte[8 * 1024];
		int bytesRead;
		while ((bytesRead = initialStream.read(buffer)) != -1) {
			outStream.write(buffer, 0, bytesRead);
		}
		IOUtils.closeQuietly(initialStream);
		IOUtils.closeQuietly(outStream);
	}
}
