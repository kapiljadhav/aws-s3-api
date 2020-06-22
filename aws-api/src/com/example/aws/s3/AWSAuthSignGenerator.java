package com.example.aws.s3;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.SimpleTimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
/**
 * 
 * @author Kapil
 *
 */
public class AWSAuthSignGenerator {

	public static byte[] computeHmacSHA256(byte[] key, String data) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
            UnsupportedEncodingException {
        String algorithm = "HmacSHA256";
        String charsetName = "UTF-8";

        Mac sha256_HMAC = Mac.getInstance(algorithm);
        SecretKeySpec secret_key = new SecretKeySpec(key, algorithm);
        sha256_HMAC.init(secret_key);

        return sha256_HMAC.doFinal(data.getBytes(charsetName));
    }

    public static byte[] computeHmacSHA256(String key, String data) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
            UnsupportedEncodingException {
        return computeHmacSHA256(key.getBytes(), data);
    }

    public static String getSignatureV4(String accessSecretKey, String date, String region, String regionService, String signing, String stringToSign)
            throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException {

        byte[] dateKey = computeHmacSHA256(accessSecretKey, date);

        byte[] dateRegionKey = computeHmacSHA256(dateKey, region);

        byte[] dateRegionServiceKey = computeHmacSHA256(dateRegionKey, regionService);

        byte[] signingKey = computeHmacSHA256(dateRegionServiceKey, signing);

        byte[] signature = computeHmacSHA256(signingKey, stringToSign);

        return Hex.encodeHexString(signature);
    }

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, UnsupportedEncodingException {
        // http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-post-example.html
    	final String accessKey = "ENTER YOUR AWS ACCESS KEY HERE";
    	final String keySecret = "ENTER YOUR ACCESS SECRET HERE";
    	
        String region = "ENTER REGION";
        String bucket = "YOUR S3 BUCKET";
        // file name
        String key = "KEY";
        
        // file content to be written in s3.
        String payloadHash = "File content goes here.";
   
        
        String regionService = "s3";
		String accessSecretKey = "AWS4" + keySecret;
        String signing = "aws4_request";
        
       
        payloadHash = DigestUtils.sha256Hex(payloadHash);
        
        Date currentDate = new Date();
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
		
		String date = dateFormat.format(currentDate);
        dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
		dateFormat.setTimeZone(new SimpleTimeZone(0, "UTC"));
        
		String amzDate = dateFormat.format(currentDate);
        
        String host = bucket+".s3.amazonaws.com";
        List<String> signedHeaderList = Arrays.asList("host", "x-amz-content-sha256", "x-amz-date");
        String signedHeaders = String.join(";", signedHeaderList);
		
		String canonicalRequest = "PUT\n" + 
        		"/" + key + "\n" + 
        		"\n" + 
        		"host:" + host + "\n" + 
        		"x-amz-content-sha256:" + payloadHash + "\n" + 
        		"x-amz-date:" + amzDate + "\n" + 
        		"\n" + 
        		signedHeaders + "\n" + 
        		payloadHash;
        
        String sha256Hex = DigestUtils.sha256Hex(canonicalRequest);

        String algorithm = "AWS4-HMAC-SHA256";
        
		String stringToSign = algorithm + "\n" + 
        		amzDate + "\n" + 
        		date + "/" + region + "/" + regionService + "/" + signing + "\n" + 
        		sha256Hex;

        String signatureV4 = "Signature=" + getSignatureV4(accessSecretKey, date, region, regionService, signing, stringToSign);
        String credentials = "Credential=" + String.join("/", Arrays.asList(accessKey, date, region, regionService, signing));
        String signedHeaderString = "SignedHeaders=" + signedHeaders;
        
        
        String authorizationHeader = algorithm + " " + credentials + "," + signedHeaderString + "," + signatureV4;
        
		System.out.println("Authorization:" + authorizationHeader);
		System.out.println("X-Amz-Content-Sha256:" + payloadHash);
		System.out.println("X-Amz-Date:" + amzDate);
    }

}