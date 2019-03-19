/*
 * Copyright 2019 Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

package com.alexa.atsapi;

import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.TimeZone;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.SignatureException;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.cognitoidentity.model.Credentials;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class ATS {
  private static final String SERVICE_HOST = "ats.api.alexa.com";
  private static final String SERVICE_URI = "/api";
  private static final String SERVICE_REGION = "us-east-1";
  private static final String SERVICE_NAME = "execute-api";
  private static final String AWS_BASE_URL = "https://" + SERVICE_HOST + SERVICE_URI;
  private static final String HASH_ALGORITHM = "HmacSHA256";
  private static final String DATEFORMAT_AWS = "yyyyMMdd'T'HHmmss'Z'";
  private static final String DATEFORMAT_CREDENTIAL = "yyyyMMdd";

  private static final String credentialsFile = ".alexa.credentials";

  public Credentials credentials = null;
  public static String provider = "";
  public CognitoHelper helper = null;
  public String amzDate;
  public String dateStamp;

  public String username = "";
  public String password = "";
  public String apikey = "";
  public String country = "";

  public ATS(String[] args) {
    this.helper = new CognitoHelper();

    this.username = args[0];
    this.password = args[1];
    this.apikey = args[2];
    this.country = args[3];
  }

  private void setDate() {
    Date now = new Date();
    SimpleDateFormat formatAWS = new SimpleDateFormat(DATEFORMAT_AWS);
    formatAWS.setTimeZone(TimeZone.getTimeZone("GMT"));
    this.amzDate = formatAWS.format(now);

    SimpleDateFormat formatCredential = new SimpleDateFormat(DATEFORMAT_CREDENTIAL);
    formatCredential.setTimeZone(TimeZone.getTimeZone("GMT"));
    this.dateStamp = formatCredential.format(now);

  }

  public static void main(String[] args) {
      String provider = "";


      if (args.length < 4) {
          System.err.println("Usage: UrlInfo USER PASSWORD API_KEY COUNTRY");
          System.exit(-1);
      }

      ATS atsClient = new ATS(args);

      if (!ValidateUser(atsClient))
        System.exit(1);

      try {
        callATS(atsClient);
      } catch (java.io.IOException exp) {
          System.out.println("IO Exception thrown" + exp);
      } catch (java.lang.Exception exp) {
          System.out.println("Exception thrown " + exp);
      }
  }

  String sha256(String textToHash) throws Exception {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] byteOfTextToHash=textToHash.getBytes("UTF-8");
      byte[] hashedByteArray = digest.digest(byteOfTextToHash);
      return bytesToHex(hashedByteArray);
  }

  static byte[] HmacSHA256(String data, byte[] key) throws Exception {
      Mac mac = Mac.getInstance(HASH_ALGORITHM);
      mac.init(new SecretKeySpec(key, HASH_ALGORITHM));
      return mac.doFinal(data.getBytes("UTF8"));
  }

  public static String bytesToHex(byte[] bytes) {
      StringBuffer result = new StringBuffer();
      for (byte byt : bytes) result.append(Integer.toString((byt & 0xff) + 0x100, 16).substring(1));
      return result.toString();
  }

  /**
   * Generates a V4 Signature key for the service/region
   *
   * @param key         Initial secret key
   * @param dateStamp   Date in YYYYMMDD format
   * @param regionName  AWS region for the signature
   * @param serviceName AWS service name
   * @return byte[] signature
   * @throws Exception
   */
  static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
      byte[] kSecret = ("AWS4" + key).getBytes("UTF8");
      byte[] kDate = HmacSHA256(dateStamp, kSecret);
      byte[] kRegion = HmacSHA256(regionName, kDate);
      byte[] kService = HmacSHA256(serviceName, kRegion);
      byte[] kSigning = HmacSHA256("aws4_request", kService);
      return kSigning;
  }


  /**
   * Makes a request to the specified Url and return the results as a String
   *
   * @param atsClient
   * @return the XML document as a String
   * @throws IOException
   */
  private static void callATS(ATS atsClient)  throws IOException, Exception {

      String canonicalQuery = "Action=TopSites&Count=10&CountryCode=" + atsClient.country + "&ResponseGroup=Country";

      String accessKey  = atsClient.credentials.getAccessKeyId();
      String secretKey = atsClient.credentials.getSecretKey();
      String sessionToken = atsClient.credentials.getSessionToken();

      atsClient.setDate();

      String canonicalHeaders = "host:" + SERVICE_HOST + "\n" + "x-amz-date:" + atsClient.amzDate + "\n";
      String signedHeaders = "host;x-amz-date";

      String payloadHash = atsClient.sha256("");

      String canonicalRequest = "GET" + "\n" + SERVICE_URI + "\n" + canonicalQuery + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash;

      // ************* TASK 2: CREATE THE STRING TO SIGN*************
      // Match the algorithm to the hashing algorithm you use, either SHA-1 or
      // SHA-256 (recommended)
      String algorithm = "AWS4-HMAC-SHA256";
      String credentialScope = atsClient.dateStamp + "/" + SERVICE_REGION + "/" + SERVICE_NAME + "/" + "aws4_request";
      String stringToSign = algorithm + '\n' +  atsClient.amzDate + '\n' +  credentialScope + '\n' +  atsClient.sha256(canonicalRequest);

      // ************* TASK 3: CALCULATE THE SIGNATURE *************
      // Create the signing key
      byte[] signingKey = atsClient.getSignatureKey(secretKey, atsClient.dateStamp, SERVICE_REGION, SERVICE_NAME);

      // Sign the string_to_sign using the signing_key
      String signature = bytesToHex(HmacSHA256(stringToSign, signingKey));

      String uri = AWS_BASE_URL + "?" + canonicalQuery;

      System.out.println("Making request to:\n");
      System.out.println(uri + "\n");

      // Make the Request

      String authorization = algorithm + " " + "Credential=" + accessKey + "/" + credentialScope + ", " +  "SignedHeaders=" + signedHeaders + ", " + "Signature=" + signature;

      String xmlResponse = makeRequest(uri, authorization, atsClient.amzDate, sessionToken, atsClient.apikey);

      // Print out the XML Response

      System.out.println("Response:\n");
      System.out.println(xmlResponse);

  }

  /**
   * Makes a request to the specified Url and return the results as a String
   *
   * @param requestUrl url to make request to
   * @return the XML document as a String
   * @throws IOException
   */
  public static String makeRequest(String requestUrl, String authorization, String amzDate, String sessionToken, String apikey) throws IOException {
      URL url = new URL(requestUrl);
      HttpURLConnection conn = (HttpURLConnection) url.openConnection();
      conn.setRequestProperty("Accept", "application/xml");
      conn.setRequestProperty("Content-Type", "application/json");
      conn.setRequestProperty("X-Amz-Date", amzDate);
      conn.setRequestProperty("Authorization", authorization);
      conn.setRequestProperty("x-amz-security-token", sessionToken);
      conn.setRequestProperty("x-api-key", apikey);

      InputStream in = (conn.getResponseCode() / 100 == 2 ? conn.getInputStream() : conn.getErrorStream());


      // Read the response
      BufferedReader replyReader =
              new BufferedReader
                      (new InputStreamReader
                              (conn.getInputStream()));
      String line;
      String replyString = "";
      while ((line = replyReader.readLine()) != null) {
          replyString = replyString.concat(line + "\n");
          }

      replyReader.close();

      return replyString;
  }

  private static void SerializeCredentials(Credentials credentials) throws java.io.IOException
  {
    ObjectOutputStream oos = null;
    FileOutputStream fout = null;
    try{
        fout = new FileOutputStream(ATS.credentialsFile, true);
        oos = new ObjectOutputStream(fout);
        oos.writeObject(credentials);
    } catch (Exception ex) {
        ex.printStackTrace();
    } finally {
        if(oos != null){
            oos.close();
        }
        if (fout != null) {
          fout.close();
        }
    }
  }

  private static Credentials DeSerializeCredentials() throws java.io.IOException
  {
    ObjectInputStream objectinputstream = null;
    try {
        FileInputStream streamIn = new FileInputStream(ATS.credentialsFile);
        objectinputstream = new ObjectInputStream(streamIn);
        Credentials credentials = (Credentials) objectinputstream.readObject();
        Date credsExpiration = credentials.getExpiration();
        Date now = new Date();
        return (credsExpiration.compareTo(now) > 0) ? credentials : null;
    } catch (Exception e) {
        return null;
    } finally {
        if(objectinputstream != null){
            objectinputstream .close();
        }
    }
  }
  /**
   * This method validates the user by entering username and password
   *
   * @param helper CognitoHelper class for performing validations
   */
  private static boolean ValidateUser(ATS atsClient) {

      try {
        atsClient.credentials = DeSerializeCredentials();
        if (atsClient.credentials != null) {
          System.out.println("Reusing credentials");
          return true;
        }
      } catch (java.io.IOException ex) {
        ;
      }
      String result = atsClient.helper.ValidateUser(atsClient.username, atsClient.password);
      if (result == null) {
          System.out.println("Username/password is invalid.");
          return false;
      }

      JSONObject payload = CognitoJWTParser.getPayload(result);
      atsClient.provider = payload.get("iss").toString().replace("https://", "");

      atsClient.credentials = atsClient.helper.GetCredentials(provider, result);

      try {
        SerializeCredentials(atsClient.credentials);
      } catch (java.io.IOException ex) {
          ex.printStackTrace();
          return false;
      }
      return true;
  }

}
