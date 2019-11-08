<?php
namespace SapiStudio\Domain;

/** PublicSuffix*/

class PublicSuffix
{
    const PUBLIC_URL = 'https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat';
    
    /** PublicSuffix::getTlds()*/
    public static function getTlds()
    {
        $list = @fopen(self::PUBLIC_URL,'r');
        while ($line = fgets($list)) {
            $line = trim($line);
            if (trim($line) == '' || (strpos(trim($line), '//') === 0)) {
                continue;
            }
            $parts = explode('.', $line);
            $tldMaster = (count($parts) == 1) ? $line : end($parts);
            $tlds[$tldMaster][] = $line;

        }
        fclose($list);
        return $tlds;
    }
}
