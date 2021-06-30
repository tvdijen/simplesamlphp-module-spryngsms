<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\spryngsms\Controller;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\Logger;
use SimpleSAML\Module\spryngsms\Controller;
use SimpleSAML\Module\spryngsms\Utils\OTP as OTPUtils;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Spryng\SpryngRestApi\Http\Response;
use Spryng\SpryngRestApi\Objects\Message;
use Symfony\Component\HttpFoundation\Request;

/**
 * Set of tests for the controllers in the "spryngsms" module.
 *
 * @covers \SimpleSAML\Module\spryngsms\Controller\OTP
 */
class OTPTest extends TestCase
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Utils\HTTP */
    protected Utils\HTTP $httpUtils;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /** @var string $otpHash */
    protected string $otpHash;


    /**
     * Set up for each test.
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->config = Configuration::loadFromArray(
            [
                'module.enable' => [
                    'spryngsms' => true,
                ],
            ],
            '[ARRAY]',
            'simplesaml',
        );

        $this->session = Session::getSessionFromRequest();

        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(
                [
                    'protected' => true,
                    'auth' => 'admin',
                    'api_key' => 'secret',
                ],
                '[ARRAY]',
                'simplesaml',
            ),
            'module_spryngsms.php',
            'simplesaml',
        );

        $this->httpUtils = new Utils\HTTP();
    }


    /**
     */
    public function testEnterCodeMissingState(): void
    {
        $request = Request::create(
            '/enterCode',
            'GET',
        );

        $c = new Controller\OTP($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing AuthState parameter.');

        $response = $c->enterCode($request);
    }


    /**
     */
    public function testEnterCode(): void
    {
        $request = Request::create(
            '/enterCode',
            'GET',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [];
            }
        });

        $response = $c->enterCode($request);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     */
    public function testValidateCodeMissingState(): void
    {
        $request = Request::create(
            '/validateCode',
            'GET',
        );

        $c = new Controller\OTP($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing AuthState parameter.');

        $response = $c->validateCode($request);
    }


    /**
     */
    public function testValidateCodeCorrect(): void
    {
        $request = Request::create(
            '/validateCode',
            'POST',
            [
                'AuthState' => 'someState',
                'otp' => '123456',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:hash' => '$2y$10$X9n7ylaGdlwomlxR7Amix.FThsOdglyNO1RYYveoshKldom49U1tC', // 123456
                    'spryngsms:timestamp' => time() - 1,
                ];
            }
        });

        $response = $c->validateCode($request);
        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals([Auth\ProcessingChain::class, 'resumeProcessing'], $response->getCallable());
    }


    /**
     */
    public function testValidateCodeIncorrect(): void
    {
        $request = Request::create(
            '/validateCode',
            'POST',
            [
                'AuthState' => 'someState',
                'otp' => '654321',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setHttpUtils($this->httpUtils);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:hash' => '$2y$10$X9n7ylaGdlwomlxR7Amix.FThsOdglyNO1RYYveoshKldom49U1tC', // 123456
                    'spryngsms:timestamp' => time() - 1,
                ];
            }
        });

        $response = $c->validateCode($request);
        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals([$this->httpUtils, 'redirectTrustedURL'], $response->getCallable());
        $this->assertEquals('http://localhost/simplesaml/module.php/spryngsms/enterCode', $response->getArguments()[0]);
    }


    /**
     */
    public function testValidateCodeExpired(): void
    {
        $request = Request::create(
            '/validateCode',
            'POST',
            [
                'AuthState' => 'someState',
                'otp' => '123456',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setHttpUtils($this->httpUtils);
        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:hash' => '$2y$10$X9n7ylaGdlwomlxR7Amix.FThsOdglyNO1RYYveoshKldom49U1tC', // 123456
                    'spryngsms:timestamp' => time() - 800, // They expire after 600 by default
                ];
            }
        });

        $response = $c->validateCode($request);
        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals([$this->httpUtils, 'redirectTrustedURL'], $response->getCallable());
        $this->assertEquals('http://localhost/simplesaml/module.php/spryngsms/resendCode', $response->getArguments()[0]);
    }


    /**
     */
    public function testsendCodeMissingState(): void
    {
        $request = Request::create(
            '/sendCode',
            'GET',
        );

        $c = new Controller\OTP($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing AuthState parameter.');

        $response = $c->sendCode($request);
    }


    /**
     */
    public function testsendCodeSuccess(): void
    {
        $request = Request::create(
            '/sendCode',
            'POST',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setLogger(new class () extends Logger {
            public static function info(string $str): void
            {
                // do nothing
            }
        });

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:recipient' => '31612345678',
                    'spryngsms:originator' => 'PHPUNIT',
                ];
            }
        });

        $c->setOtpUtils(new class () extends OTPUtils {
            public function sendMessage(string $api_key, string $code, string $recipient, string $originator): Response
            {
                return new class () extends Response {
                    /**
                     * Indicates if this was a successful request by evaluating the response code.
                     *
                     * @return bool
                     */
                    public function wasSuccessful() {
                        return true;
                    }

                    /**
                     * Return a deserialized object from the response
                     *
                     * @return Message|Balance|MessageCollection
                     */
                    public function toObject() {
                        return new class () extends Message {
                            /**
                             * @return mixed
                             */
                            public function getId()
                            {
                                return '9dbc5ffb-7524-4fae-9514-51decd94a44f';
                            }
                        };
                    }
                };
            }
        });

        $response = $c->sendCode($request);
        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals([$this->httpUtils, 'redirectTrustedURL'], $response->getCallable());
        $this->assertEquals('http://localhost/simplesaml/module.php/spryngsms/enterCode', $response->getArguments()[0]);
    }


    /**
     */
    public function testsendCodeFailureServer(): void
    {
        $request = Request::create(
            '/sendCode',
            'POST',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setLogger(new class () extends Logger {
            public static function error(string $str): void
            {
                // do nothing
            }
        });

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:recipient' => '31612345678',
                    'spryngsms:originator' => 'PHPUNIT',
                ];
            }
        });

        $c->setOtpUtils(new class () extends OTPUtils {
            public function sendMessage(string $api_key, string $code, string $recipient, string $originator): Response
            {
                return new class () extends Response {
                    /**
                     * Indicates if this was a successful request by evaluating the response code.
                     *
                     * @return bool
                     */
                    public function wasSuccessful() {
                        return false;
                    }

                    /**
                     * Indicates if a failed request was a fault of the server
                     *
                     * @return bool
                     */
                    public function serverError()
                    {
                        return true;
                    }
                };
            }
        });

        $response = $c->sendCode($request);
        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals([$this->httpUtils, 'redirectTrustedURL'], $response->getCallable());
        $this->assertEquals('http://localhost/simplesaml/module.php/spryngsms/promptResend', $response->getArguments()[0]);
    }



    /**
     */
    public function testsendCodeFailureOther(): void
    {
        $request = Request::create(
            '/sendCode',
            'POST',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:recipient' => '31612345678',
                    'spryngsms:originator' => 'PHPUNIT',
                ];
            }
        });

        $c->setLogger(new class () extends Logger {
            public static function error(string $str): void
            {
                // do nothing
            }
        });

        $c->setOtpUtils(new class () extends OTPUtils {
            public function sendMessage(string $api_key, string $code, string $recipient, string $originator): Response
            {
                return new class () extends Response {
                    /**
                     * Indicates if this was a successful request by evaluating the response code.
                     *
                     * @return bool
                     */
                    public function wasSuccessful() {
                        return false;
                    }

                    /**
                     * Indicates if a failed request was a fault of the server
                     *
                     * @return bool
                     */
                    public function serverError()
                    {
                        return false;
                    }

                   /**
                     * @return mixed
                     */
                    public function getResponseCode()
                    {
                        return 401;
                    }
                };
            }
        });

        $response = $c->sendCode($request);
        $this->assertInstanceOf(RunnableResponse::class, $response);
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals([$this->httpUtils, 'redirectTrustedURL'], $response->getCallable());
        $this->assertEquals('http://localhost/simplesaml/module.php/spryngsms/promptResend', $response->getArguments()[0]);
    }


    /**
     */
    public function testPromptResendMissingState(): void
    {
        $request = Request::create(
            '/promptResend',
            'GET',
        );

        $c = new Controller\OTP($this->config, $this->session);

        $this->expectException(Error\BadRequest::class);
        $this->expectExceptionMessage('Missing AuthState parameter.');

        $response = $c->promptResend($request);
    }


    /**
     */
    public function testPromptResendExpired(): void
    {
        $request = Request::create(
            '/promptResend',
            'GET',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:expired' => true
                ];
            }
        });

        $response = $c->promptResend($request);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     */
    public function testPromptResendSendFailure(): void
    {
        $request = Request::create(
            '/promptResend',
            'GET',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:sendFailure' => 'something went wrong'
                ];
            }
        });

        $response = $c->promptResend($request);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     */
    public function testPromptResendRequested(): void
    {
        $request = Request::create(
            '/promptResend',
            'GET',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                    'spryngsms:resendRequested' => true
                ];
            }
        });

        $response = $c->promptResend($request);

        $this->assertInstanceOf(Template::class, $response);
        $this->assertTrue($response->isSuccessful());
    }


    /**
     */
    public function testPromptResendUnknownReason(): void
    {
        $request = Request::create(
            '/promptResend',
            'GET',
            [
                'AuthState' => 'someState',
            ]
        );

        $c = new Controller\OTP($this->config, $this->session);

        $c->setAuthState(new class () extends Auth\State {
            public static function loadState(string $id, string $stage, bool $allowMissing = false): ?array
            {
                return [
                ];
            }
        });

        $this->expectException(RuntimeException::class);
        $c->promptResend($request);
    }
}
