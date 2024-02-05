<?php
namespace SapiStudio\Domain\Analyzer;
use Illuminate\Support\Collection;

/** DmarcAnalyzer*/

class DmarcAnalyzer
{
    protected $dmarcLine            = null;
    protected $dmarcLineParsed      = [];
    protected $dmarcLineDetailed    = [];
    protected $dmarcTags            = [];
    protected $validDmarcLine       = false;
    
    /** DmarcAnalyzer::create() */
    public static function create($dmarcLine = null)
    {
        return new static($dmarcLine);
    }
    
    /** DmarcAnalyzer::__construct() */
    public function __construct($dmarcLine){
        $this->loadDmarcTags();
        $this->setDmarcLine($dmarcLine);
    }
    
    /** DmarcAnalyzer::getDmarcLine() */
    public function getDmarcLine(){
        return $this->dmarcLine;
    }
    
    /** DmarcAnalyzer::setDmarcLine()*/
    public function setDmarcLine($dmarcLine){
        $this->dmarcLine = $dmarcLine;
        $this->parseDmarcLine();
    }
    
    /** DmarcAnalyzer::getDetailDmARC() */
    public function getDetailDmARC(){
        return ($this->dmarcIsValid()) ? $this->dmarcLineDetailed :  false;
    }
    
    /**  DmarcAnalyzer::loadDmarcTags() */
    public function loadDmarcTags(){
        $this->dmarcTags = include(dirname(__FILE__).'/../config/dmarcTags.php');
    }
    
    /** DmarcAnalyzer::dmarcIsValid() */
    public function dmarcIsValid(){
        return $this->validDmarcLine;
    }
    
    /** DmarcAnalyzer::parseDmarcLine() */
    protected function parseDmarcLine(){
        if($this->dmarcLine && preg_match("/^v=dmarc(.*)/i", $this->dmarcLine)){
            $result = $detailed_result = [];
            $dmarcLine  = array_filter(array_map("trim",explode(';',$this->dmarcLine)));
            array_walk($dmarcLine, function($value,$key) use (&$result,&$detailed_result){
                list($tag,$tagvalue) = explode("=", $value);
                $result[$tag] = $tagvalue;
                $detailed_result[$tag] = ['description' => $this->dmarcTags[$tag]['description'],'value' => $tagvalue];
            });
            $this->dmarcLineParsed      = Collection::make($result);
            $this->dmarcLineDetailed    = Collection::make($detailed_result);
            $this->validDmarcLine       = true;
        }
        return $this;
    }
}
