/*
 * Copyright 2019 Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the MIT License. See the LICENSE accompanying this file
 * for the specific language governing permissions and limitations under
 * the License.
 */

<?php
/**
 * Makes a request to ATS for the top 10 sites in a country
 */
class TopSites {

    protected static $ActionName            = 'Topsites';
    protected static $ResponseGroupName     = 'Country';
    protected static $ServiceHost           = 'ats.stage.api.alexa.com';
    protected static $NumReturn             = 10;
    protected static $StartNum              = 1;
    protected static $ServiceURI            = "/api";

    public function TopSites($apiKey,  $countryCode) {
        $now = time();
        $this->countryCode = $countryCode;
        $this->apiKey = $apiKey;
    }

    /**
     * Get site info from ATS.
     */
    public function getTopSites() {
        $canonicalQuery = $this->buildQueryParams();

        $url = 'https://' . self::$ServiceHost . self::$ServiceURI . '?' . $canonicalQuery;
        $ret = self::makeRequest($url);
        echo $ret;
    }

    /**
     * Builds query parameters for the request to AWIS.
     * Parameter names will be in alphabetical order and
     * parameter values will be urlencoded per RFC 3986.
     * @return String query parameters for the request
     */
     protected function buildQueryParams() {
         $params = array(
           'Action'            => self::$ActionName,
           'ResponseGroup'     => self::$ResponseGroupName,
           'CountryCode'       => $this->countryCode,
           'Count'             => self::$NumReturn,
           'Start'             => self::$StartNum
         );
         ksort($params);
         $keyvalue = array();
         foreach($params as $k => $v) {
             $keyvalue[] = $k . '=' . rawurlencode($v);
         }
         return implode('&',$keyvalue);
     }

     /**
      * Makes request to TopSites
      * @param String $url   URL to make request to
      * @param String authorizationHeader  Authorization string
      * @return String       Result of request
      */
    protected function makeRequest($url) {
        echo "\nMaking request to:\n$url\n";
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_TIMEOUT, 4);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
          'Accept: application/xml',
          'Content-Type: application/xml',
          'x-api-key: ' . $this->apiKey
        ));
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
    }
}

if (count($argv) < 3) {
    echo "Usage: $argv[0] API_KEY COUNTRY_CODE\n";
    exit(-1);
}
else {
    $apiKey = $argv[1];
    $countryCode = $argv[2];
}

$topSites = new TopSites($apiKey, $countryCode);
$topSites->getTopSites();

?>
