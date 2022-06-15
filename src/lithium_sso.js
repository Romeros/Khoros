/**
 * lithium_sso.js
 * version 1.0.0
 * Created on May 31, 2022
 *
 * Copyright (C) 2006 Lithium Technologies, Inc. 
 * Emeryville, California, U.S.A.  All Rights Reserved.
 *
 * This software is the  confidential and proprietary information
 * of  Lithium  Technologies,  Inc.  ("Confidential Information")
 * You shall not disclose such Confidential Information and shall 
 * use  it  only in  accordance  with  the terms of  the  license 
 * agreement you entered into with Lithium.
 *
 * Example Usage:
 *
 * // Secret SSO key (128-bit or 256-bit) provided by Lithium
 * sso_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
 *
 * // (Optional) Secret PrivacyGuard key (128-bit or 256-bit) *NOT* to be shared with Lithium
 * pg_key = "";
 *
 * // Initialize Lithium SSO Client
 * const lithium_sso = require("./lithium_sso");
 * const lithium = new lithium_sso("example", ".example.com", sso_key, server_id = "", HTTP_USER_AGENT,  HTTP_REFERER, REMOTE_ADDR);
 *
 * // (Optional) Additional user profile settings to pass to Lithium
 * settings = object {};
 *
 * // Example: Set the user's homepage URL
 * settings {
 * "profile.url_homepage" : "http://myhomepage.example.com"
 * };
 *
 * // Example: Grant the user the Moderator role
 * settings {
 * "roles.grant" : "Moderator"
 * };
 *
 * // Create the authentication token
 * lithium.get_auth_token("1000", "myscreenname", "myemail@example.com", settings).then(liToken => {
 *     res.status(200).json({ sso_token: liToken });
 * });
 *
 * The token can either be passed directly through HTTP GET/POST, or through cookies.
 *
 * If PrivacyGuard is enabled, you must initialize the PrivacyGuard key, and call the encryption function
 * for each token which requires PG encryption. Example:
 *
 * lithium.init_smr(pg_hex_key);
 * pg_enc_parameter = lithium.get_smr_field("myemail@example.com");
 * lithium.get_auth_token("1000", "myscreenname", pg_enc_parameter, settings").then(liToken => {
 *     res.status(200).json({ sso_token: liToken });
 * });
 *
 */
const sprintf = require('sprintf-js').sprintf;
const JSMTRand = require('js_mt_rand');
const number_format = require('locutus/php/strings/number_format');
const crypto = require('crypto');
const zlib = require('zlib');

class lithium_sso {
	
	/**
	 * Constructor
	 * 
	 * @param client_id The client or community id to create an SSO token for
	 * @param client_domain The domain name for this token, used when transporting via
	 *                       cookies (i.e. ".lithium.com")
	 * @param sso_hex_key The 128-bit or 256-bit secret key, represented in hexadecimal
	 */
	 constructor (client_id, client_domain, sso_hex_key, server_id = "", HTTP_USER_AGENT,  HTTP_REFERER, REMOTE_ADDR) {
		this.HTTP_USER_AGENT = HTTP_USER_AGENT;
		this.HTTP_REFERER = HTTP_REFERER;
		this.REMOTE_ADDR = REMOTE_ADDR;
	/**
	 * Constants
	 */
	 this.lithium_separator = "|";
	 this.lithium_version = "LiSSOv1.5";
	 this.lithium_cookie_name = "lithiumSSO%3A";
 
	 this.ANONYMOUS_UNIQUE_ID = '$LiAnonPlz$';

		if (!client_id) throw new Error("Could not initialize Lithium SSO Client: Client id required");
		if (!client_domain) throw new Error("Could not initialize Lithium SSO Client: Client domain required");
		if (!sso_hex_key) throw new Error("Could not initialize Lithium SSO Client: SSO Hex key required");

		this.client_id = client_id;
		this.client_domain = client_domain;
		this.server_id = this.parse_server_id(server_id);
		if(typeof sso_hex_key === "string"){
			this.sso_key = Buffer.from(sso_hex_key, "hex");
		}else{
			this.sso_key = sso_hex_key;
		}

		if (this.sso_key.length != 16 && this.sso_key.length != 32) {
			throw new Error("SSO key must be 128-bit or 256-bit in length");
		}
		
		this.tsid = Date.now();
	}
	
	/**
	 * Returns a Lithium authentication token for the given user parameters
	 * 
	 * @param unique_id A non-changable id used to uniquely identify this user globally.
	 *                   This should be an non-reusable integer or other identifier.  
	 *                   E-mail addresses can be used, but are not recommended as this 
	 *                   value cannot be changed.
	 * @param login     The login name or screen name for this user.  This is usually
	 *                   a publicly visible field, so should not contain personally
	 *                   identifiable information.
	 * @param email     The e-mail address for this user.
	 * @param settings 	An object of profile settings => value pairs.
	 *                   Examples of settings include:
	 *                   roles.grant = Moderator (grants the Moderator role to user)
	 *                   profile.name_first = John (sets first name to John)
	 *                   Contact Lithium for a list of valid settings.
	 *
	 * @return string the encrypted authentication token
	 */
	async get_auth_token(unique_id, login, email, settings) {
		return await this.get_auth_token_value(unique_id, login, email, settings, this.HTTP_USER_AGENT, this.HTTP_REFERER, this.REMOTE_ADDR);
	}

	/**
	 * Returns a Lithium authentication token for the given user parameters
	 * 
	 * @param unique_id A non-changable id used to uniquely identify this user globally.
	 *                   This should be an non-reusable integer or other identifier.  
	 *                   E-mail addresses can be used, but are not recommended as this 
	 *                   value cannot be changed.
	 * @param login     The login name or screen name for this user.  This is usually
	 *                   a publicly visible field, so should not contain personally
	 *                   identifiable information.
	 * @param email     The e-mail address for this user.
	 * @param settings An object of profile settings => value pairs.
	 *                   Examples of settings include:
	 *                   roles.grant = Moderator (grants the Moderator role to user)
	 *                   profile.name_first = John (sets first name to John)
	 *                   Contact Lithium for a list of valid settings.
	 * @param req_user_agent [this.HTTP_USER_AGENT] used for security
	 *                   identification information.
	 * @param req_referer [this.HTTP_REFERER] used for security
	 *                   identification information.
	 * @param req_remote_addr [this.REMOTE_ADDR] used for security
	 *                   identification information.
	 *
	 * @return string the encrypted authentication token
	 */
	async get_auth_token_value(unique_id, login, email, settings, req_user_agent, req_referer, req_remote_addr) {
		if (!unique_id) throw new Error("Could not create Lithium token: Unique id required");
		if (!login) throw new Error("Could not create Lithium token: Login name required");
		if (!email) throw new Error("Could not create Lithium token: E-mail address required");

		let settings_string = (JSON.stringify(settings)).replaceAll(":", "=").replaceAll(",", "|").replaceAll("\"", "").replace("{", "").replace("}", "");
		this.tsid ++;

		let raw_string;
		raw_string = "Li";
		raw_string += this.lithium_separator;
		raw_string += this.lithium_version;
		raw_string += this.lithium_separator;
		raw_string += this.server_id;
		raw_string += this.lithium_separator;
		raw_string += number_format( this.tsid, 0, '', '' );
		raw_string += this.lithium_separator;
		raw_string += Date.now();
		raw_string += this.lithium_separator;
		raw_string += this.get_token_safe_string(req_user_agent);
		raw_string += this.lithium_separator;
		raw_string += this.get_token_safe_string(req_referer);
		raw_string += this.lithium_separator;
		raw_string += this.get_token_safe_string(req_remote_addr);
		raw_string += this.lithium_separator;
		raw_string += this.client_domain;
		raw_string += this.lithium_separator;
		raw_string += this.client_id;
		raw_string += this.lithium_separator;
		raw_string += this.get_token_safe_string(unique_id);
		raw_string += this.lithium_separator;
		raw_string += this.get_token_safe_string(login);
		raw_string += this.lithium_separator;
		raw_string += this.get_token_safe_string(email);
		raw_string += this.lithium_separator;
		raw_string += settings_string;
		raw_string += "iL";
		let encoded = await this.encode(raw_string, this.sso_key);
		return encoded;
	}

	/**
	 * Returns an encrypted representation of the specified string.
	 *
	 * @access private
	 * @param string the string to encode
	 * @param string the key to use
	 *
	 * @return string the encoded string
	 */
	async encode(string, key) {

		let encoded = string;
		encoded = zlib.deflateSync(encoded);
  		// AES
		let iv = this.get_random_iv(16);
		encoded = this.openssl_encrypt(encoded, `AES-${key.length * 8}-CBC`, key, iv);
		// URL Base64
		encoded = encoded.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '.');
  
		// Version and IV Prefix
		encoded = `~2${iv}~${encoded}`;
		  
		return encoded;
	}

    /**
	 * Returns a random initialization vector for AES with the specified length.
	 * The returned string is URL-safe.
	 *
	 * @access private
	 * @param length the length of the IV to return, in bytes
	 * 
	 * @return string the IV in string form
	 */
	get_random_iv(length) {
		const valid_chars = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		let iv = "";
		for (let i=0; i<length; i++) {
			iv += valid_chars[Math.round(Math.random()*(valid_chars.length - 1))];
		}
		return iv;
	}

    /**
	 * Returns a token-safe representation of the specified string.  Used to ensure that
	 * the token separator is not used inside a token.
	 * 
	 * @access private
	 * @param string the string to return a token-safe representation for
	 * 
	 * @return string the token-safe representation of string
	 */
	get_token_safe_string(string) {
		return string.replace("|", "-");
	}

	/**
	 * PrivacyGuard key init
	 * 
	 * @param pg_hex_key The 128-bit or 256-bit PrivacyGuard key, represented in hexadecimal
	 */
	init_smr(pg_hex_key) {
		if (!pg_hex_key) throw new Error("Could not initialize Lithium SSO Client: PrivacyGuard Hex key required");

		this.pg_key = Buffer.from(pg_hex_key, "hex");//pack("H*", pg_hex_key);
		if (this.pg_key.length != 16 && this.pg_key.length != 34) {
			throw new Error("PG key must be 128-bit or 256-bit in length");
		}
	}

	/**
	 * PrivacyGuard parameter encrypt
	 * 
	 * @param string the string to return a PrivacyGuard encrypted token for
	 * 
	 * @return string the the PrivacyGuard encrypted value of string or "" if no key set.
	 */
	get_smr_field(string) {
		if (this.pg_key) {
			return this.encode(string, this.pg_key);
		} else {
			return "";
		}
	}
	
	parse_server_id(id) {
		id = id.trim();
		const hex_string = this.get_random_hex_string(32);
		
		if (id.length != 0) {
				id = this.get_token_safe_string(id);
			} else {
				id = "34";
		}
		
		return sprintf("%s-%s", id, hex_string);
	}
	
	get_random_hex_string(length) {
		let str = "";
		let mt = new JSMTRand();
		
		while (str.length < length) {
			str += sprintf("%02X", mt.rand(0, 255));
		}
		
		return str;
	}

openssl_encrypt(encoded, AES_METHOD, key, iv){

    if (process.versions.openssl <= '1.0.1f') {
        throw new Error('OpenSSL Version too old, vulnerability to Heartbleed');
    }
    let cipher = crypto.createCipheriv(AES_METHOD, key, iv);
    let encrypted = cipher.update(encoded, 'utf8', 'base64');
	encrypted += cipher.final('base64');

    return encrypted;
	}
}
module.exports = lithium_sso;