<?php
namespace SapiStudio\Domain\Analyzer;
use Illuminate\Support\Collection;

/**
 * DmarcAnalyzer
 * 
 */

class DmarcAnalyzer
{
    protected $dmarcLine        = null;
    protected $dmarcLineParsed  = [];
    protected $dmarcTags        = [];
    
    /**
     * DmarcAnalyzer::create()
     */
    public static function create($dmarcLine = null)
    {
        return new static($dmarcLine);
    }
    
    /**
     * DmarcAnalyzer::__construct()
     */
    public function __construct($dmarcLine){
        if(!$dmarcLine)
            throw new \InvalidArgumentException('A dmarc line is needed');
        $this->loadDmarcTags();
        $this->setDmarcLine($dmarcLine);
        $this->parseDmarcLine();
    }
    
    /**
     * DmarcAnalyzer::getDmarcPolicy()
     */
    public function getDmarcPolicy(){
        return $this->dmarcLineParsed->get('p','none');
    }
    
    /**
     * DmarcAnalyzer::loadDmarcTags()
     */
    public function loadDmarcTags(){
        $this->dmarcTags = include(dirname(__FILE__).'/../config/dmarcTags.php');
    }
    
    /**
     * DmarcAnalyzer::parseDmarcLine()
     */
    public function parseDmarcLine(){
        $result     = [];
        $dmarcLine  = array_filter(array_map("trim",explode(';',$this->dmarcLine)));
        array_walk($dmarcLine, function($value,$key) use (&$result){
            list($tag,$tagvalue) = explode("=", $value);
            $result[$tag] = $tagvalue;
});
        $this->dmarcLineParsed = Collection::make($result);
        return $this;
    }
    
    /**
     * DmarcAnalyzer::getDmarcLine()
     */
    public function getDmarcLine(){
        return $this->dmarcLine;
    }
    
    /**
     * DmarcAnalyzer::setDmarcLine()
     */
    public function setDmarcLine($dmarcLine){
        $this->dmarcLine = $dmarcLine;
    }
}