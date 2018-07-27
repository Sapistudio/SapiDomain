# DnsRecords

## Check ip or domain against blacklists
```php
use SapiStudio\DnsRecords\Querifier;

Querifier::blacklistLookup($ipValue);
```

## Get all DNS records for a domain
```php
use SapiStudio\DnsRecords\Querifier;

Querifier::hostLookup($domainName);
```

## Initialize querifier with a custom getter(dig or php)
```php
use SapiStudio\DnsRecords\Querifier;

$querifier = Querifier::make($domainName,Querifier::GETTER_PHP);//or Querifier::GETTER_DIG
//load all records
$querifier->loadDnsRecords();
//get txt entries
$querifier->getTxtRecords();
```
