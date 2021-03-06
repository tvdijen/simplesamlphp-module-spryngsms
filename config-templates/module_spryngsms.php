<?php

/*
 * The configuration of SimpleSAMLphp spryngsms package
 */

$config = [
    // Whether the statistics require authentication before use.
    'protected' => true,

    // The authentication source that should be used.
    'auth' => 'admin',

    // The Spryng REST API key
    'api_key' => 'secret',

    // The originator for the SMS
    // 'originator' => 'Spryng',

    // The attribute containing the user's mobile phone number
    // 'mobilePhoneAttribute' => 'mobile',
];
