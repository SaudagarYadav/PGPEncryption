package com.pgpEncryption.service;

import java.io.ByteArrayInputStream;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import com.pgpEncryption.bean.SftpRequest;

public class SFTPService {

	private static final String  STRICT_HOST_KEY_CHECKING = "StrictHostKeyChecking";
	private static final String SFTP = "sftp";

	public static ChannelSftp getSftpConnection(SftpRequest req) throws JSchException {
		Properties config = new java.util.Properties();
		config.put(STRICT_HOST_KEY_CHECKING, "no");

		JSch ssh = new JSch();
		if (req.getPrivateKeyLocation()!=null && 
				!req.getPrivateKeyLocation().isEmpty()) {
			ssh.addIdentity(req.getPrivateKeyLocation());
		}
		final Session session = ssh.getSession(req.getUserName(), req.getHostUrl(), req.getPort());
		session.setConfig(config);
		session.setPassword(req.getPassword());
		session.connect();

		ChannelSftp channelSftp = (ChannelSftp) session.openChannel(SFTP);
		channelSftp.connect();
		System.out.println("SFTP connected successfully");
		return channelSftp;
	}
	

	public static void uploadStoredFile(final ChannelSftp channelSftp , final String srcFilelocation, final String disFileLocation) throws SftpException {
		channelSftp.put(srcFilelocation, disFileLocation);
		System.out.println("SFTP (uploadStoredFile) - File uploaded successfully at " + disFileLocation);
	}

	public static Set<String> getFolderFiles(final ChannelSftp channelSftp, final String directory, final String format) throws SftpException {
		var fileList = new HashSet<String>();
		channelSftp.cd(directory);
		Vector<ChannelSftp.LsEntry> srcFileList = channelSftp.ls("*." + format);
		System.out.println("SFTP (getFolderFiles) - Number. of files at " + directory + " is " + srcFileList.size());
		for (ChannelSftp.LsEntry entry : srcFileList) {
			fileList.add(entry.getFilename());
		}
		return fileList;
	}
	
	/**
	 * This method is used to upload file to SFTP location
	 * @param channelSftp
	 * @param fileContent
	 * @param distinationFileLocation
	 * @throws SftpException 
	 */
	public static void uploadFile(final ChannelSftp channelSftp , final String fileContent, final String distinationFileLocation) throws SftpException {
		channelSftp.put(new ByteArrayInputStream( fileContent.getBytes()), distinationFileLocation);
		System.out.println("SFTP (uploadFile) - File uploaded successfully");
	}
	
	/**
	 * This method is used to close all connection
	 * @param channelSftp
	 * @throws JSchException 
	 */
	public static void disconnectChannelSftp(final ChannelSftp channelSftp) throws JSchException {
		if (channelSftp == null)
			return;

		if (channelSftp.isConnected())
			channelSftp.disconnect();

		if (channelSftp.getSession() != null)
			channelSftp.getSession().disconnect();
		System.out.println("SFTP disconnected successfully");
	}


}
