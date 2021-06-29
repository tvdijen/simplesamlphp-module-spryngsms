<?php

/**
 * SMS Authentication Processing filter
 *
 * Filter for requesting the user's SMS-based OTP.
 *
 * @package tvdijen/simplesamlphp-module-spryngsms
 */

declare(strict_types=1);

namespace SimpleSAML\Module\spryngsms\Auth\Process;

use RuntimeException;
use SAML2\Constants;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Module\spryngsms\Utils\OTP as OTPUtils;
use SimpleSAML\Utils;
use UnexpectedValueException;

class OTP extends Auth\ProcessingFilter
{
    // The REST API key for the Spryng SMS service
    private string $api_key;

    // The originator for the SMS
    private string $originator;

    // The attribute containing the user's mobile phone number
    private string $mobilePhoneAttribute;


    /**
     * Initialize SMS OTP filter.
     *
     * Validates and parses the configuration.
     *
     * @param array $config Configuration information.
     * @param mixed $reserved For future use.
     *
     * @throws \SimpleSAML\Error\ConfigurationError if the required REST API key is missing.
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $moduleConfig = Configuration::getConfig('module_spryngsms.php');
        $api_key = $moduleConfig->getString('api_key', null);
        Assert::notNull(
            $api_key,
            'Missing required REST API key for the Spryng service.',
            Error\ConfigurationError::class
        );

        $originator = $moduleConfig->getString('originator', 'Spryng SMS');
        Assert::notEmpty($originator, 'Originator cannot be an empty string', Error\ConfigurationError::class);
        Assert::alnum($originator, 'Originator must be an alphanumeric string', Error\ConfigurationError::class);

        $mobilePhoneAttribute = $moduleConfig->getString('mobilePhoneAttribute', 'mobile');
        Assert::notEmpty(
            $mobilePhoneAttribute,
            'mobilePhoneAttribute cannot be an empty string',
            Error\ConfigurationError::class
        );

        $this->api_key = $api_key;
        $this->originator = $originator;
        $this->mobilePhoneAttribute = $mobilePhoneAttribute;
    }


    /**
     * Process a authentication response
     *
     * This function saves the state, and redirects the user to the page where the user can enter the OTP
     * code sent to them.
     *
     * @param array &$request The state of the response.
     */
    public function process(array &$request): void
    {
        // user interaction necessary. Throw exception on isPassive request
        if (isset($request['isPassive']) && $request['isPassive'] === true) {
            throw new Module\saml\Error\NoPassive(
                Constants::STATUS_REQUESTER,
                'Unable to enter verification code on passive request.'
            );
        }

        // Retrieve the user's mobile phone number
        $recipient = $this->getMobilePhoneAttribute($request);

        // Sanitize the user's mobile phone number
        $otpUtils = new OTPUtils();
        $recipient = $otpUtils->sanitizeMobilePhoneNumber($recipient);

        // Generate the OTP
        $code = $otpUtils->generateOneTimePassword();

        Assert::digits($code, UnexpectedValueException::class);
        Assert::length($code, 6, UnexpectedValueException::class);

        // Send SMS
        $otpUtils->sendMessage($this->api_key, $code, $recipient, $this->originator);

        // Salt & hash it
        $cryptoUtils = new Utils\Crypto();
        $hash = $cryptoUtils->pwHash($code);

        // Store hash & time
        $request['spryngsms:hash'] = $hash;
        $request['spryngsms:timestamp'] = time();

        // Save state and redirect
        $id = Auth\State::saveState($request, 'spryngsms:request');
        $url = Module::getModuleURL('spryngsms/validateCode');

        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, ['StateId' => $id]);
    }


    /**
     * Retrieve the mobile phone attribute from the state
     *
     * @param array $state
     * @return string
     * @throws \RuntimeException if no attribute with a mobile phone number is present.
     */
    protected function getMobilePhoneAttribute(array $state): string
    {
        if (
            !array_key_exists('Attributes', $state)
            || !array_key_exists($this->mobilePhoneAttribute, $state['Attributes'])
        ) {
            throw new RuntimeException(
                sprintf(
                    "spryngsms:OTP: Missing attribute '%s', which is needed to send an SMS.",
                    $this->mobilePhoneAttribute
                )
            );
        }

        return $state['Attributes'][$this->mobilePhoneAttribute][0];
    }
}
