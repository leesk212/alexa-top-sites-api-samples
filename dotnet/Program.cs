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
using System.Security;
using System.Web;
using System.Linq;
using System.Collections;
using System.Collections.Generic;

namespace dotnet_core_ats
{
    class Program
    {
        static private async Task api(string[] args)
        {
			    var request = new HttpRequestMessage {
      		Method = HttpMethod.Get,
			        RequestUri = new Uri("https://ats.stage.api.alexa.com/api?Action=TopSites&Count=5&CountryCode=" +args[1] + "&ResponseGroup=Country")
			    };

          request.Headers.Add("x-api-key", args[0]);

			    var client = new HttpClient();
			    var response = await client.SendAsync(request);

			    var responseStr = await response.Content.ReadAsStringAsync();
          Console.WriteLine(responseStr);
        }

        static void Main(string[] args)
        {
          if (args.Length != 2) {
            Console.WriteLine("Usage: dotnet run API_KEY COUNTRY");
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
