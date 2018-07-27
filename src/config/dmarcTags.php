<?php

return [
        "v" => [
            "description"   => "Version of the DMARC",
            "required"      => true,
            "aspected"      => ["DMARC1"]
        ],
        "p" => [
            "description"   => "Policy to apply to email that fails the DMARC check",
            "required"      => true,
            "aspected"      => ["none","quarantine","reject"]
        ],
        "rua" => [
            "description"   => "The list of URIs for receivers to send XML feedback to.Ex: mailto:address@example.org",
            "required"      => false,
            "aspected"      => false
        ],
        "pct" => [
            "description"   => "The percentage tag tells receivers to only apply policy against email that fails the DMARC check X amount of the time",
            "required"      => false,
            "aspected"      => false
        ],
        "adkim" => [
            "description"   => "Specifies Alignment Mode for DKIM signatures. 'r' is for Relaxed, 's' is for Strict.",
            "required"      => false,
            "aspected"      => false
        ],
        "aspf" => [
            "description"   => "Specifies Alignment Mode for SPF signatures. 'r' is for Relaxed, 's' is for Strict.",
            "required"      => false,
            "aspected"      => false
        ],
        "sp" => [
            "description"   => "Policy to apply to email from a sub-domain of this DMARC record that fails the DMARC check. This tag allows domain owners to explicitly publish a wildcard sub-domain policy.",
            "required"      => false,
            "aspected"      => false
        ],
        "fo" => [
            "description"   => "Forensic reporting options. Possible values: '0' to generate reports if all underlying authentication mechanisms fail to produce a DMARC pass result, '1' to generate reports if any mechanisms fail, 'd' to generate report if DKIM signature failed to verify, 's' if SPF failed.",
            "required"      => false,
            "aspected"      => false
        ],
        "ruf" => [
            "description"   => "The list of URIs for receivers to send Forensic reports to.Ex: mailto:address@example.org",
            "required"      => false,
            "aspected"      => false
        ],
        "rf" => [
            "description"   => "The reporting format for individual Forensic reports.",
            "required"      => false,
            "aspected"      => ["afrf","iodef"]
        ],
        "ri" => [
            "description"   => "The reporting interval for how often you'd like to receive aggregate XML reports.",
            "required"      => false,
            "aspected"      => false
        ]
];
