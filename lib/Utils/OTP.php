<?php

/**
 * Utilities for SMS-based OTP.
 *
 * @package tvdijen/simplesamlphp-module-spryngsms
 */

declare(strict_types=1);

namespace SimpleSAML\Module\spryngsms\Utils;

use SimpleSAML\Assert\Assert;
use Spryng\SpryngRestApi\Http\Response;
use Spryng\SpryngRestApi\Objects\Message;
use Spryng\SpryngRestApi\Spryng;
use UnexpectedValueException;

class OTP
{
    /**
     * Send OTP SMS
     *
     * @param string $code
     * @param string $recipient
     * @return \Spryng\SpryngRestApi\Http\Response
     */
    public function sendMessage(string $api_key, string $code, string $recipient, string $originator): Response
    {
        $spryng = new Spryng($api_key);

        $message = new Message();
        $message->setBody($code);
        $message->setRecipients([$recipient]);
        $message->setOriginator($originator);

        return $spryng->message->create($message);
    }


    /**
     * Generate a 6-digit random code
     *
     * @return string
     */
    public function generateOneTimePassword(): string
    {
        $code = sprintf("%06d", mt_rand(10000, 999999));
        $padded = str_pad($code, 6, '0', STR_PAD_LEFT);

        return $padded;
    }


    /**
     * Sanitize the mobile phone number for use with the Spryng Rest API
     *
     * @param string $recipient
     * @return string
     * @throws \UnexpectedValueException if the mobile phone number contains illegal characters or is otherwise invalid.
     */
    public function sanitizeMobilePhoneNumber(string $recipient): string
    {
        $recipient = preg_replace('/^([+]|[0]{1,2})?(.*)/', '$2', $recipient);
        $recipient = str_replace('-', '', $recipient);

        Assert::notEmpty($recipient, 'spryngsms:OTP: mobile phone number cannot be an empty string.');
        Assert::digits($recipient, UnexpectedValueException::class);

        return $recipient;
    }
}
