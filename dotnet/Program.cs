/*
 * Copyright 2019 Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

using System;
using System.Net.Http;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using Aws4RequestSigner;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web;
using System.Linq;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentity.Model;
using System.Collections;
using System.Collections.Generic;

namespace dotnet_core_ats
{
  [Serializable]
    class UserCognitoCredentials
    {
      String accessKey;
      String secretKey;
      String sessionToken;
      DateTime expiration;

      public UserCognitoCredentials(Amazon.CognitoIdentity.Model.Credentials credentials)
      {
        this.accessKey = credentials.AccessKeyId;
        this.secretKey = credentials.SecretKey;
        this.sessionToken = credentials.SessionToken;
        this.expiration = credentials.Expiration;
      }

      public String getAccessKey() {
        return this.accessKey;
      }

      public String getSecretKey() {
        return this.secretKey;
      }

      public String getSessionToken() {
        return this.sessionToken;
      }

      public DateTime getExpiration() {
        return this.expiration;
      }
    }

    class Program
    {
      static String credentialsFile = @".alexa.credentials";

        static private void saveCredentials(UserCognitoCredentials credentials)
        {
          IFormatter formatter = new BinaryFormatter();
          Stream stream = new FileStream(credentialsFile, FileMode.Create, FileAccess.Write);

          formatter.Serialize(stream, credentials);
          stream.Close();
        }

        static private UserCognitoCredentials getSavedCredentials()
        {
          UserCognitoCredentials credentials = null;
          try {
            IFormatter formatter = new BinaryFormatter();
            Stream stream = new FileStream(credentialsFile, FileMode.Open, FileAccess.Read);
            credentials = (UserCognitoCredentials)formatter.Deserialize(stream);
            if (DateTime.UtcNow > credentials.getExpiration()) {
              Console.WriteLine(String.Format("Saved credentials expired ({0} older than {1})", credentials.getExpiration(), DateTime.UtcNow));
              credentials = null;
            } else {
              Console.WriteLine(String.Format("Using saved credentials. Valid until {0}", credentials.getExpiration()));
            }
          } catch (IOException) {
            credentials = null;
          }
          return credentials;
        }

        static private async Task<UserCognitoCredentials> getCognitoCredentials(String userEmail, String userPassword)
        {
          String cognitoUserPoolId = "us-east-1_n8TiZp7tu";
          String cognitoClientId = "6clvd0v40jggbaa5qid2h6hkqf";
          String cognitoIdentityPoolId = "us-east-1:bff024bb-06d0-4b04-9e5d-eb34ed07f884";
          Amazon.RegionEndpoint cognitoRegion = Amazon.RegionEndpoint.USEast1;

          AmazonCognitoIdentityProviderClient provider =
              new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), Amazon.RegionEndpoint.USEast1);
          CognitoUserPool userPool = new CognitoUserPool(cognitoUserPoolId, cognitoClientId, provider);
          CognitoUser user = new CognitoUser(userEmail, cognitoClientId, userPool, provider);

          AuthFlowResponse context = await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
              {
                  Password = userPassword
              }).ConfigureAwait(false);

          String accessToken = context.AuthenticationResult.AccessToken;
          String idToken = context.AuthenticationResult.IdToken;

          CognitoAWSCredentials credentials =
              user.GetCognitoAWSCredentials(cognitoIdentityPoolId, cognitoRegion);

          var identityClient = new AmazonCognitoIdentityClient(credentials, cognitoRegion);
          var idRequest = new Amazon.CognitoIdentity.Model.GetIdRequest();
          idRequest.IdentityPoolId = cognitoIdentityPoolId;
          idRequest.Logins = new Dictionary<string,string> {  {"cognito-idp.us-east-1.amazonaws.com/"+cognitoUserPoolId , idToken } };
          var idResponseId = await identityClient.GetIdAsync(idRequest).ConfigureAwait(false);
          if (idResponseId.HttpStatusCode != System.Net.HttpStatusCode.OK) {
            Console.WriteLine(String.Format("Failed to get credentials for identity. Status code: {0} ", idResponseId.HttpStatusCode));
            System.Environment.Exit(1);
          }

          var idResponseCredential = await identityClient.GetCredentialsForIdentityAsync(idResponseId.IdentityId, new Dictionary<string,string> {  {"cognito-idp.us-east-1.amazonaws.com/"+cognitoUserPoolId , idToken } }).ConfigureAwait(false);
          if (idResponseCredential.HttpStatusCode != System.Net.HttpStatusCode.OK) {
            Console.WriteLine(String.Format("Failed to get credentials for identity. Status code: {0} ", idResponseCredential.HttpStatusCode));
            System.Environment.Exit(1);
          }

          var cognitoCredentials = new UserCognitoCredentials(idResponseCredential.Credentials);

          return cognitoCredentials;
        }

        static private async Task api(string[] args)
        {
          UserCognitoCredentials credentials = getSavedCredentials();
          if (credentials == null) {
            credentials = getCognitoCredentials(args[0], args[1]).Result;
            saveCredentials(credentials);
          }

            var signer = new AWS4RequestSigner(credentials.getAccessKey(), credentials.getSecretKey());
				    var request = new HttpRequestMessage {
        		Method = HttpMethod.Get,
				        RequestUri = new Uri("https://ats.api.alexa.com/api?Action=TopSites&Count=5&CountryCode=" +args[3] + "&ResponseGroup=Country")
				    };

            request.Headers.Add("x-api-key", args[2]);
            request.Headers.Add("x-amz-security-token", credentials.getSessionToken());

			    request = await signer.Sign(request, "execute-api", "us-east-1");

			    var client = new HttpClient();
			    var response = await client.SendAsync(request);

			    var responseStr = await response.Content.ReadAsStringAsync();
          Console.WriteLine(responseStr);
        }

        static void Main(string[] args)
        {
          if (args.Length != 4) {
            Console.WriteLine("Usage: dotnet run user password API_KEY COUNTRY");
            System.Environment.Exit(1);
          }
          try{
            api(args).Wait();
          }catch(Exception ex){
            Console.WriteLine(ex);
          }
        }
    }
}
