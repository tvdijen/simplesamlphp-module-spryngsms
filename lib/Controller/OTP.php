<?php

namespace SimpleSAML\Module\spryngsms\Controller;

//use Exception;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
//use SimpleSAML\HTTP\RunnableResponse;
//use SimpleSAML\Locale\Translate;
//use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

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
//    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Session */
    protected Session $session;

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
//        $this->moduleConfig = Configuration::getConfig('module_spryngsms.php');
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
        $id = $request->get('StateId', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing required StateId query parameter.');
        }

        $state = $this->authState::loadState($id, 'spryngsms:request');

        $t = new Template($this->config, 'spryngsms:entercode.twig');
//        $t->data = [
//        ];

        return $t;
    }


    /**
     * Process the entered validation code.
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function validateCode(Request $request): RedirectResponse
    {
    }
}
