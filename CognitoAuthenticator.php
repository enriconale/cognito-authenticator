<?php
namespace Enrico\CognitoAws;

require_once('lib/aws/aws-autoloader.php');
require_once('CustomBCMath.php');

use Aws\Sdk;
use Exception;

class CognitoAuthenticator
{
    // https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
    const INIT_N = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD' .
                  'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
                  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' .
                  '83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
                  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510' .
                  '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' .
                  'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' .
                  'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';

    // https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
    const G_HEX = '2';

    // https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L55
    const INFO_BITS = 'Caldera Derived Key';

    var $bigN;
    var $g;
    var $k;
    var $smallAValue;
    var $largeAValue;

    var $_sdk;
    var $_cognitoClient;
    var $_username;
    var $_password;
    var $_userPoolId;
    var $_clientId;
    var $_awsKey;
    var $_awsSecret;

    public function __construct($awsAccessKey, $awsSecretKey, $username, $password, $userPoolId, $clientId)
    {
        //Mandatory values needed for authentication. Use your auth data here.
        $this->_awsKey = $awsAccessKey;
        $this->_awsSecret = $awsSecretKey;
        $this->_username = $username;
        $this->_password = $password;
        $this->_userPoolId = $userPoolId;
        $this->_clientId = $clientId;

        //Change this config according to your location
        $sharedConfig = [
            'client' => 'cognito-idp',
            'region' => 'eu-west-1',
            'version' => 'latest',
            'credentials' => array(
                'key' => $this->_awsKey,
                'secret'  => $this->_awsSecret
            )
        ];

        // Create an SDK class used to share configuration across clients.
        $this->_sdk = new Sdk($sharedConfig);
        $this->_cognitoClient = $this->_sdk->createCognitoIdentityProvider();
    }

    /**
     * This method will start a full challenge-response authentication flow with the Amazon Cognito Service.
     * This flow is an implementation of the Secure Remote Password protocol (SRP).
     *
     * @return mixed|null an array of tokens needed for authentication
     *
     * @throws Exception if the challenge is different from PASSWORD_VERIFIER
     */
    public function getAccessTokenFromFullAuthentication()
    {
        $this->bigN = $this->getDecimalFromHex(self::INIT_N);
        $this->g = $this->getDecimalFromHex(self::G_HEX);
        $this->k = $this->getDecimalFromHex($this->hexHash('00' . self::INIT_N . '0' . self::G_HEX));
        $this->smallAValue = $this->calcLittleRandomA($this->bigN);
        $this->largeAValue = $this->calcA($this->g, $this->smallAValue, $this->bigN);

        $initiateAuthResponse = $this->_cognitoClient->initiateAuth(array(
            'AuthFlow' => 'USER_SRP_AUTH',
            'AuthParameters' => array(
                "USERNAME" => $this->_username,
                "SRP_A" => $this->getHexFromDecimal($this->largeAValue)
            ),
            'ClientId' => $this->_clientId,
            'UserPoolId' => $this->_userPoolId,
        ));

        if ($initiateAuthResponse->get('ChallengeName') == 'PASSWORD_VERIFIER') {
            $challengeResponse = $this->processAuthChallenge($initiateAuthResponse);
            $authResult = $this->_cognitoClient->respondToAuthChallenge(array(
                'ChallengeName' => 'PASSWORD_VERIFIER',
                'ChallengeResponses' => $challengeResponse,
                'ClientId' => $this->_clientId
            ));
        } else {
            throw new Exception('This challenge is not supported: ' . $initiateAuthResponse->get('ChallengeName'));
        }

        return $authResult->get('AuthenticationResult');
    }

    /**
     * Get a new Access Token using the Refresh Token received during the full authentication flow.
     *
     * @param $refreshToken
     *
     * @return \Aws\Result|mixed|null
     * @throws Exception
     */
    public function getAccessTokenFromRefreshToken($refreshToken)
    {
        try {
            $tokens = $this->_cognitoClient->initiateAuth(array(
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => array(
                    'USERNAME' => $this->_username,
                    'REFRESH_TOKEN' => $refreshToken
                ),
                'ClientId' => $this->_clientId,
            ));
        } catch (Exception $e) {
            //Fallback to standard auth if the refresh doesn't work
            $tokens = $this->getAccessTokenFromFullAuthentication();

            return $tokens;
        }


        return $tokens->get('AuthenticationResult');
    }

    /**
     * Process the authentication challenge received from the server.
     *
     * @param $initiateAuthResponse
     *
     * @return array
     * @throws Exception
     */
    private function processAuthChallenge($initiateAuthResponse)
    {
        $challengeParameters = $initiateAuthResponse->get('ChallengeParameters');
        $user_id_for_srp = $challengeParameters['USER_ID_FOR_SRP'];
        $salt_hex = $challengeParameters['SALT'];
        $srp_b_hex = $challengeParameters['SRP_B'];
        $secret_block_b64 = $challengeParameters['SECRET_BLOCK'];

        $format_string = "%a %b %-d %H:%M:%S UTC %Y";
        $timestamp = strftime($format_string, time());

        $hkdf = $this->getPasswordAuthenticationKey(
            $user_id_for_srp,
            $this->_password,
            $this->getDecimalFromHex($srp_b_hex),
            $salt_hex);

        $secret_block_bytes = base64_decode($secret_block_b64);

        $msg = utf8_encode(explode('_', $this->_userPoolId)[1]) . utf8_encode($user_id_for_srp) .
            $secret_block_bytes . utf8_encode($timestamp);
        $hmac_obj = hash_hmac('sha256', $msg, $hkdf, true);
        $signature_string = base64_encode($hmac_obj);

        return array("TIMESTAMP" => $timestamp,
                     "USERNAME" => $user_id_for_srp,
                     "PASSWORD_CLAIM_SECRET_BLOCK" => $secret_block_b64,
                     "PASSWORD_CLAIM_SIGNATURE" => utf8_decode($signature_string));
    }

    /**
     * Compute the HKDF key.
     *
     * @param $username
     * @param $password
     * @param $serverBValue
     * @param $salt
     *
     * @return bool|string
     * @throws Exception
     */
    private function getPasswordAuthenticationKey($username, $password, $serverBValue, $salt)
    {
        $uVal = $this->calcU($this->largeAValue, $serverBValue);
        if ($uVal == '0') {
            throw new Exception('U variable cannot be zero');
        }

        $usernamePassword = explode('_', $this->_userPoolId)[1] . $username . ':' . $password;
        $usernamePasswordHash = hash('sha256', utf8_encode($usernamePassword));
        $xValue = $this->getDecimalFromHex($this->hexHash($this->padHex($salt) . $usernamePasswordHash));
        $g_mod_pow_xn = CustomBCMath::customBcPowMod($this->g, $xValue, $this->bigN);
        $int_value2 = bcsub($serverBValue, bcmul($this->k , $g_mod_pow_xn));
        $s_value = CustomBCMath::customBcMod(CustomBCMath::customBcPowMod($int_value2, bcadd($this->smallAValue, bcmul($uVal, $xValue)), $this->bigN), $this->bigN);

        $hkdfKey = $this->computeHKDFKey(hex2bin($this->padHex($s_value)), hex2bin($this->padHex($this->getHexFromDecimal($uVal))));

        return $hkdfKey;
    }

    private function hexHash($hexString)
    {
        return hash( 'sha256' , hex2bin($hexString));
    }

    private function getDecimalFromHex($hex)
    {
        $dec = 0;
        $len = strlen($hex);
        for ($i = 1; $i <= $len; $i++) {
            $dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));
        }

        return $dec;
    }

    private function getHexFromDecimal($dec)
    {
        $hex = '';
        do {
            $last = CustomBCMath::customBcMod($dec, '16');
            $hex = dechex($last) . $hex;
            $dec = bcdiv(bcsub($dec, $last), '16');
        } while ($dec > 0);

        return $hex;
    }

    private function calcLittleRandomA($bigN)
    {
        return CustomBCMath::customBcMod($this->getDecimalFromHex(bin2hex(openssl_random_pseudo_bytes(128))), $bigN);
    }

    private function calcA($g, $smallAValue, $bigN)
    {
        $bigA = CustomBCMath::customBcPowMod($g, $smallAValue, $bigN);

        return $bigA;
    }

    private function calcU($bigA, $bigB)
    {
        $HexHashOfU = $this->hexHash($this->padHex($bigA) . $this->padHex($bigB));

        return $this->getDecimalFromHex($HexHashOfU);
    }

    private function padHex($hexNumber)
    {
        if (is_numeric($hexNumber)) {
            $hashString = $this->getHexFromDecimal($hexNumber);
        } else {
            $hashString = $hexNumber;
        }
        if (strlen($hashString) % 2 == 1) {
            $hashString = '0' . $hashString;
        } elseif (strpos('89ABCDEFabcdef', $hashString[0]) !== false) {
            $hashString = '00' . $hashString;
        }

        return $hashString;
    }

    private function computeHKDFKey($ikm, $salt)
    {
        $prk = hash_hmac('sha256', $ikm, $salt, true);
        $infoBitsUpdate = utf8_encode(self::INFO_BITS) . utf8_encode(chr(1));
        $HMACHash = hash_hmac('sha256', $infoBitsUpdate, $prk, true);

        return substr($HMACHash, 0, 16);
    }
}
