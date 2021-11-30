package com.pgpEncryption.bean;

public class SftpRequest {

	private String hostUrl;
	private int port;
	private String userName;
	private String password;
	private String privateKeyLocation;
	private String location;

	public String getHostUrl() {
		return hostUrl;
	}

	public void setHostUrl(String hostUrl) {
		this.hostUrl = hostUrl;
	}

	public SftpRequest(String hostUrl, int port, String userName, String password, String privateKeyLocation,
			String location) {
		super();
		this.hostUrl = hostUrl;
		this.port = port;
		this.userName = userName;
		this.password = password;
		this.privateKeyLocation = privateKeyLocation;
		this.location = location;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPrivateKeyLocation() {
		return privateKeyLocation;
	}

	public void setPrivateKeyLocation(String privateKeyLocation) {
		this.privateKeyLocation = privateKeyLocation;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

}
