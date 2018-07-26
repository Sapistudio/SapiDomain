<?php
return[
    "ipBased" => [
       "cbl.abuseat.org" => [
            "name"      => "Composite Blocking List",
            "shortName" => "CBL",
       ],
       "sbl.spamhaus.org" => [
            "name"      => "Spamhaus Block List",
            "shortName" => "SBL",
       ],
       "xbl.spamhaus.org" => [
            "name"      => "Exploits Block List",
            "shortName" => "XBL",
       ],
       "pbl.spamhaus.org" => [
            "name"      => "Policy Block List",
            "shortName" => "PBL",
       ],
       "zen.spamhaus.org" => [
            "name"      => "",
            "shortName" => "ZEN",
       ],
       "bl.spamcop.net" => [
            "name"      => "Spamcop",
            "shortName" => "SCBL",
       ],
       "psbl.surriel.com" => [
            "name"      => "Passive Spam Block List",
            "shortName" => "PSBL",
       ],
       "dnsbl.invaluement.com" => [
            "name"      => "Invaluement",
            "shortName" => "DNSBL",
       ],
       "b.barracudacentral.org" => [
            "name"      => "Barracuda",
            "shortName" => "Barracuda",
       ],
       "ubl.unsubscore.com" => [
            "name"      => "Lashback",
            "shortName" => "UBL",
       ],
       /**
       "query.senderbase.org" => [
            "name"      => "Senderbase",
            "shortName" => "Senderbase",
       ],
       */
       "multi.surbl.org" => [
            "name"      => "surbl",
            "shortName" => "surbl",
       ]
    ],
    "domainBased" => [
        "dbl.spamhaus.org" => [
            "name"      => "Spamhaus DBL",
            "shortName" => "DBL",
       ],
       "multi.surbl.org" => [
            "name"      => "SURBL",
            "shortName" => "SURBL",
       ]
    ]
  ];