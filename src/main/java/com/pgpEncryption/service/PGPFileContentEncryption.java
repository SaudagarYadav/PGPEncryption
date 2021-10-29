package com.pgpEncryption.service;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

public class PGPFileContentEncryption {

	public boolean encryptFile(String publicKey, String unencryptedFile, String tempFilePath) {

		OutputStream out = null;
		InputStream plainInputData = null;
		try {
			out = new BufferedOutputStream(new FileOutputStream(unencryptedFile));
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PGPMessageEncryptor pgp = new PGPMessageEncryptor();
			File initialFile = new File(tempFilePath);
			plainInputData = new FileInputStream(initialFile);
			pgp.encrypt(getPublicKey(publicKey), tempFilePath, plainInputData, baos);
			out.write(baos.toByteArray());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (Objects.nonNull(out)) {
				try {
					out.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (Objects.nonNull(plainInputData)) {
				try {
					plainInputData.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return true;
	}

	public InputStream decryptAndVerify(String inputFile, String privateKey, String passphrase) {

		InputStream keyPrivate = null;
		InputStream iStream = null;
		InputStream in = null;

		try {

			in = new FileInputStream(inputFile);
			keyPrivate = getPrivateKey(privateKey);

			PGPMessageEncryptor pgp = new PGPMessageEncryptor();

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			
			pgp.decrypt(passphrase, keyPrivate, in, baos);
			iStream = new ByteArrayInputStream(baos.toByteArray());
			in.close();
			keyPrivate.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return iStream;
	}

	public InputStream getPrivateKey(String privateKey) throws Exception {
		File initialFile = new File(privateKey);
		InputStream plainInputData = new FileInputStream(initialFile);
		return plainInputData;
	}

	public InputStream getPublicKey(String publicKey) throws Exception {
		File initialFile = new File(publicKey);
		InputStream plainInputData = new FileInputStream(initialFile);
		return plainInputData;
	}
}
