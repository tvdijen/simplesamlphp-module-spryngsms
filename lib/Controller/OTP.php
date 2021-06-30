<?php

namespace SimpleSAML\Module\spryngsms\Controller;

use RuntimeException;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\spryngsms\Utils\OTP as OTPUtils;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use UnexpectedValueException;

/**
 * Controller class for the spryngsms module.
 *
 * This class serves the verification code and error views available in the module.
 *
 * @package SimpleSAML\Module\spryngsms
 */
class OTP
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Logger */
    protected Logger $logger;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /**
     * @var \SimpleSAML\Utils\HTTP|string
     * @psalm-var \SimpleSAML\Utils\HTTP|class-string
     */
    protected Utils\HTTP $httpUtils;

    /**
     * @var \SimpleSAML\Module\spryngsms\Utils\OTP|string
     * @psalm-var \SimpleSAML\Module\spryngsms\Utils\OTP|class-string
     */
    protected OTPUtils $otpUtils;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;


    /**
     * OTP Controller constructor.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use.
     * @param \SimpleSAML\Session $session The current user session.
     */
    public function __construct(Configuration $config, Session $session)
    {
        $this->config = $config;
        $this->httpUtils = new Utils\HTTP();
        $this->otpUtils = new OTPUtils();
        $this->moduleConfig = Configuration::getConfig('module_spryngsms.php');
        $this->session = $session;
    }


    /**
     * Inject the \SimpleSAML\Logger dependency.
     *
     * @param \SimpleSAML\Logger $logger
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }


    /**
     * Inject the \SimpleSAML\Utils\HTTP dependency.
     *
     * @param \SimpleSAML\Utils\HTTP $httpUtils
     */
    public function setHttpUtils(Utils\HTTP $httpUtils): void
    {
        $this->httpUtils = $httpUtils;
    }


    /**
     * Inject the \SimpleSAML\Module\spryngsms\Utils\OTP dependency.
     *
     * @param \SimpleSAML\Module\spryngsms\Utils\OTP $otpUtils
     */
    public function setOtpUtils(OTPUtils $otpUtils): void
    {
        $this->otpUtils = $otpUtils;
    }


    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }


    /**
     * Display the page where the validation code should be entered.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function enterCode(Request $request): Template
    {
        $id = $request->get('AuthState', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        $state = $this->authState::loadState($id, 'spryngsms:request');

        $t = new Template($this->config, 'spryngsms:entercode.twig');
        $t->data = [
            'AuthState' => $id,
            'stateparams' => [],
        ];

        return $t;
    }


    /**
     * Process the entered validation code.
     *
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function validateCode(Request $request): RunnableResponse
    {
        $id = $request->get('AuthState', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        $state = $this->authState::loadState($id, 'spryngsms:request');

        Assert::keyExists($state, 'spryngsms:timestamp');
        Assert::positiveInteger($state['spryngsms:timestamp']);

        $timestamp = $state['spryngsms:timestamp'];
        $validUntil = $timestamp + $this->moduleConfig->getInteger('validUntil', 600);

        // Verify that code was entered within a reasonable amount of time
        if (time() > $validUntil) {
            $state['spryngsms:expired'] = true;

            $id = Auth\State::saveState($state, 'spryngsms:request');
            $url = Module::getModuleURL('spryngsms/resendCode');

            return new RunnableResponse([$this->httpUtils, 'redirectTrustedURL'], [$url, ['AuthState' => $id]]);
        }

        Assert::keyExists($state, 'spryngsms:hash');
        Assert::stringNotEmpty($state['spryngsms:hash']);

        $cryptoUtils = new Utils\Crypto();
        if ($cryptoUtils->pwValid($state['spryngsms:hash'], $request->get('otp'))) {
            // The user has entered the correct verification code
            return new RunnableResponse([Auth\ProcessingChain::class, 'resumeProcessing'], [$state]);
        } else {
            $state['spryngsms:invalid'] = true;

            $id = Auth\State::saveState($state, 'spryngsms:request');
            $url = Module::getModuleURL('spryngsms/enterCode');

            return new RunnableResponse([$this->httpUtils, 'redirectTrustedURL'], [$url, ['AuthState' => $id]]);
        }
    }


    /**
     * Display the page where the user can trigger sending a new SMS.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function promptResend(Request $request): Template
    {
        $id = $request->get('AuthState', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        $state = $this->authState::loadState($id, 'spryngsms:request');

        $t = new Template($this->config, 'spryngsms:promptresend.twig');
        $t->data = [
            'AuthState' => $id,
        ];

        if (isset($state['spryngsms:expired']) && ($state['spryngsms:expired'] === true)) {
            $t->data['message'] = 'Your verification code has expired.';
        } elseif (isset($state['spryngsms:sendFailure'])) {
            Assert::stringNotEmpty($state['spryngsms:sendFailure']);
            $t->data['message'] = $state['spryngsms:sendFailure'];
        } elseif (isset($state['spryngsms:resendRequested']) && ($state['spryngsms:resendRequested'] === true)) {
            $t->data['message'] = '';
        } else {
           throw new RuntimeException('Unknown request for SMS resend.');
        }

        return $t;
    }


    /**
     * Send an SMS and redirect to either the validation page or the resend-prompt
     *
     * @return \SimpleSAML\HTTP\RunnableResponse
     */
    public function sendCode(Request $request): RunnableResponse
    {
        $id = $request->get('AuthState', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        $state = $this->authState::loadState($id, 'spryngsms:request');

        // Generate the OTP
        $code = $this->otpUtils->generateOneTimePassword();

        Assert::digits($code, UnexpectedValueException::class);
        Assert::length($code, 6, UnexpectedValueException::class);

        $api_key = $this->moduleConfig->getString('api_key', null);
        Assert::notNull(
            $api_key,
            'Missing required REST API key for the Spryng service.',
            Error\ConfigurationError::class
        );

        Assert::keyExists($state, 'spryngsms:recipient');
        Assert::keyExists($state, 'spryngsms:originator');

        // Send SMS
        $response = $this->otpUtils->sendMessage(
            $api_key,
            $code,
            $state['spryngsms:recipient'],
            $state['spryngsms:originator'],
        );

        if ($response->wasSuccessful()) {
            /** @var \Spryng\SpryngRestApi\Objects\Message $message */
            $message = $response->toObject();
            $this->logger::info("Message with ID " . $message->getId() . " was send successfully!");

            // Salt & hash it
            $cryptoUtils = new Utils\Crypto();
            $hash = $cryptoUtils->pwHash($code);

            // Store hash & time
            $state['spryngsms:hash'] = $hash;
            $state['spryngsms:timestamp'] = time();

            // Save state and redirect
            $id = Auth\State::saveState($state, 'spryngsms:request');
            $url = Module::getModuleURL('spryngsms/enterCode');
        } else {
            if ($response->serverError()) {
                $msg = "Message could not be send because of a server error...";
            } else {
                $msg = "Message could not be send. Response code: " . $response->getResponseCode();
            }

            $this->logger::error($msg);
            $state['spryngsms:sendFailure'] = $msg;

            // Save state and redirect
            $id = Auth\State::saveState($state, 'spryngsms:request');
            $url = Module::getModuleURL('spryngsms/promptResend');
        }

        return new RunnableResponse([$this->httpUtils, 'redirectTrustedURL'], [$url, ['AuthState' => $id]]);
    }
}
