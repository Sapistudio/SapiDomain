<?php
namespace SapiStudio\Domain\Analyzer;

/** SpfAnalyzer */

class SpfAnalyzer
{
    protected $rawRecords           = null;
    protected $parsedSpf            = null;
    
    const SPF_RESULT_PASS           = 'Spf valid';
    const SPF_RESULT_FAIL           = 'Spf fail';
    const SPF_RESULT_SOFTFAIL       = 'Spf soft fail';
    const SPF_RESULT_NEUTRAL        = '?';
    const SPF_RESULT_NONE           = 'No spf';
    const SPF_RESULT_PERMERROR      = 'Spf error';
    
    /** SpfAnalyzer::create() */
    public static function create($data = [])
    {
        return new static($data);
    }
    
    /** SpfAnalyzer::__construct()*/
    public function __construct($data){
        $this->setDnsData($data);
        $this->parseSpf();
    }
    
    /** SpfAnalyzer::parseSpf() */
    public function parseSpf(){
        if(!$this->getDnsData()){
            $this->parsedSpf = false;
            return $this;
        }
        $spfRecord  = false;
        foreach ($this->getDnsData() as $record) {
            if ($record['type'] == 'TXT') {
                $txt = strtolower($record['txt']);
                if ($txt == 'v=spf1' || stripos($txt, 'v=spf1 ') === 0)
                    $spfRecords[] = $txt;
            }
        }
        if (count($spfRecords) == 0) {
            $this->parsedSpf = self::SPF_RESULT_NONE;
        }elseif (count($spfRecords) > 1) {
            $this->parsedSpf = self::SPF_RESULT_PERMERROR;
        }else{
            $this->parsedSpf = $spfRecords[0];
        }
        return $this;
    }
    
    /** SpfAnalyzer::getSpf()*/
    public function getSpf(){
        return $this->parsedSpf;
    }
    
    /** SpfAnalyzer::getDnsData() */
    public function getDnsData(){
        return $this->rawRecords;
    }
    
    /**  SpfAnalyzer::setDnsData() */
    public function setDnsData($data){
        $this->rawRecords = $data;
    }
}
