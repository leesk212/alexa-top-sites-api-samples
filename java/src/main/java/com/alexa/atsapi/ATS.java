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
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class ATS {
  private static final String SERVICE_HOST = "ats.stage.api.alexa.com";
  private static final String SERVICE_URI = "/api";
  private static final String AWS_BASE_URL = "https://" + SERVICE_HOST + SERVICE_URI;
  public String apikey = "";
  public String country = "";

  public ATS(String[] args) {
    this.apikey = args[0];
    this.country = args[1];
  }

  public static void main(String[] args) {
      if (args.length < 2) {
          System.err.println("Usage: UrlInfo API_KEY COUNTRY");
          System.exit(-1);
      }

      ATS atsClient = new ATS(args);

      try {
        callATS(atsClient);
      } catch (java.io.IOException exp) {
          System.out.println("IO Exception thrown" + exp);
      } catch (java.lang.Exception exp) {
          System.out.println("Exception thrown " + exp);
      }
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

      String uri = AWS_BASE_URL + "?" + canonicalQuery;

      System.out.println("Making request to:\n");
      System.out.println(uri + "\n");

      // Make the Request

      String xmlResponse = makeRequest(uri, atsClient.apikey);

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
  public static String makeRequest(String requestUrl, String apikey) throws IOException {
      URL url = new URL(requestUrl);
      HttpURLConnection conn = (HttpURLConnection) url.openConnection();
      conn.setRequestProperty("Accept", "application/json");
      conn.setRequestProperty("Content-Type", "application/json");
      conn.setRequestProperty("x-api-key", apikey);

      System.out.println("Api key: " + apikey);
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
}
