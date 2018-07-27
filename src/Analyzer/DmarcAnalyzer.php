<?php
namespace SapiStudio\DnsRecords\Analyzer;
use SapiStudio\DnsRecords\Querifier;

/**
 * DmarcAnalyzer
 * 
 * @package 
 * @copyright 2017
 * @version $Id$
 * @access public
 */

class DmarcAnalyzer
{
    protected $dmarcLine        = null;
    protected $dmarcLineParsed  = [];
    protected $dmarcTags        = [];
    
    /**
     * DmarcAnalyzer::create()
     * 
     * @param mixed $dmarcLine
     * @return
     */
    public static function create($dmarcLine = null)
    {
        return new static($dmarcLine);
    }
    
    /**
     * DmarcAnalyzer::__construct()
     * 
     * @param mixed $dmarcLine
     * @return
     */
    public function __construct($dmarcLine){
        if(!$dmarcLine)
            throw new \InvalidArgumentException('A dmarc line is needed');
        $this->loadDmarcTags();
        $this->setDmarcLine($dmarcLine);
        $this->parseDmarcLine();
    }
    
    /**
     * DmarcAnalyzer::loadDmarcTags()
     * 
     * @return
     */
    public function loadDmarcTags(){
        $this->dmarcTags = include(dirname(__FILE__).'/../config/dmarcTags.php');
    }
    
    /**
     * DmarcAnalyzer::parseDmarcLine()
     * 
     * @return
     */
    public function parseDmarcLine(){
        $result     = [];
        $dmarcLine  = array_filter(array_map("trim",explode(';',$this->dmarcLine)));
        array_walk($dmarcLine, function($value,$key) use (&$result){
            list($tag,$tagvalue) = explode("=", $value);
            $result[$tag] = $tagvalue;
});
        $this->dmarcLineParsed = $result;
        return $this;
    }
    
    /**
     * DmarcAnalyzer::getDmarcLine()
     * 
     * @return
     */
    public function getDmarcLine(){
        return $this->dmarcLine;
    }
    
    /**
     * DmarcAnalyzer::setDmarcLine()
     * 
     * @param mixed $dmarcLine
     * @return
     */
    public function setDmarcLine($dmarcLine){
        $this->dmarcLine = $dmarcLine;
    }
}
