//
// Copyright 2019 Amazon.com, Inc. and its affiliates. All Rights Reserved.
//
// Licensed under the MIT License. See the LICENSE accompanying this file
// for the specific language governing permissions and limitations under
// the License.
//

const AWS = require('aws-sdk')
const rp   = require('request-promise')
const aws4 = require('aws4')
const util = require('util');

const amazonCognito = require('amazon-cognito-identity-js')

const CognitoUserPool = amazonCognito.CognitoUserPool
const AuthenticationDetails = amazonCognito.AuthenticationDetails
const CognitoUser = amazonCognito.CognitoUser


const cognitoUserPoolId = 'us-east-1_n8TiZp7tu'
const cognitoClientId = '6clvd0v40jggbaa5qid2h6hkqf'
const cognitoIdentityPoolId = 'us-east-1:bff024bb-06d0-4b04-9e5d-eb34ed07f884'
const cognitoRegion = 'us-east-1'
const awsRegion = 'us-east-1'
const apiHost = 'ats.api.alexa.com'
const credentialsFile = '.alexa.credentials'
const fs = require('fs');

AWS.config.region = awsRegion;
global.fetch = require("node-fetch");

const poolData = {
  UserPoolId: cognitoUserPoolId,
  ClientId: cognitoClientId
}



function getCognitoLoginKey() {
  return `cognito-idp.${cognitoRegion}.amazonaws.com/${cognitoUserPoolId}`
}

function getCredentials(email, password) {
  var awsCredentials = {}

  return new Promise(function(resolve, reject) {
    try {
      var contents = fs.readFileSync(credentialsFile, 'utf-8');
      awsCredentials = JSON.parse(contents);
    } catch (err) {
      awsCredentials = {'expireTime': new Date()};
    }
    var curTime = Date.now()
    if (new Date(awsCredentials.expireTime).getTime() > curTime)
      resolve(awsCredentials);
    else
      login(email, password)
        .then( (credentials)=> resolve( credentials ))
        .catch( (e)=> reject(e))
  })
}


function login(email, password) {
    const authenticationDetails = new AuthenticationDetails({
      Username: email,
      Password: password
    })

    var cognitoUser = new CognitoUser({
      Username: email,
      Pool: new CognitoUserPool(poolData)
    })
    return new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (result) => {
          AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: cognitoIdentityPoolId,
            Logins: {
              [getCognitoLoginKey()]: result.getIdToken().getJwtToken()
            }
          })

          AWS.config.credentials.refresh((error) => {
            if (error) {
              console.error(`Credentials refresh: ${error}`)
            } else {
              var awsCredentials = {
                    'accessKeyId': AWS.config.credentials.accessKeyId,
                    'secretAccessKey': AWS.config.credentials.secretAccessKey,
                    'sessionToken': AWS.config.credentials.sessionToken,
                    'expireTime': AWS.config.credentials.expireTime
              }

              fs.writeFileSync(credentialsFile, JSON.stringify(awsCredentials) , 'utf-8');
              resolve(awsCredentials);
            }
          })
        },
        onFailure: (result) => {
          console.error(`Result ${JSON.stringify(result)}`)
          reject(result);
        }
    })
  })
}


function callATS(awsCredentials, apikey, country) {
  var uri = '/api?Action=TopSites&Count=5&CountryCode=' + country + '&ResponseGroup=Country&Output=json';

  var opts = {
    host: apiHost,
    path: uri,
    uri: 'https://' + apiHost + uri,
    json: true,
    headers: {'x-api-key': apikey},
        resolveWithFullResponse: true
  }

  opts.region = awsRegion
  opts.service = 'execute-api'
  var signer  = new aws4.RequestSigner(opts, awsCredentials)

  signer.sign()

  rp(opts)
  .then( (html)=> console.log(`${JSON.stringify(html.body, null, 2)}`) )
  .catch( (e)=> console.log('failed:'+e))
}

if (process.argv.length != 6) {
  console.log(`Usage: node ${process.argv[1]} USER PASSWORD APIKEY COUNTRY`);
  process.exit(0);
}

  getCredentials(process.argv[2], process.argv[3])
    .then(function(awsCredentials) {
      callATS(awsCredentials, process.argv[4], process.argv[5])
    })
    .catch( (e)=> console.log(e))
