<?php
namespace SapiStudio\DnsRecords\Getter;

interface RecordInterface
{
    /**
     * queryDns()
     * 
     * @return
     */
    public function queryDns($type);
}