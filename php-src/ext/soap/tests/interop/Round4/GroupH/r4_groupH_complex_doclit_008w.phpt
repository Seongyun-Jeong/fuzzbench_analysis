--TEST--
SOAP Interop Round4 GroupH Complex Doc Lit 008 (php/wsdl): echoMultipleFaults2(2)
--EXTENSIONS--
soap
--INI--
soap.wsdl_cache_enabled=0
--FILE--
<?php
class SOAPStruct {
    function __construct(public $varString, public $varInt, public $varFloat) {}
}
class BaseStruct {
    function __construct(public $structMessage, public $shortMessage) {}
}
class ExtendedStruct extends BaseStruct {
    function __construct(
        $structMessage, $shortMessage,
        public $stringMessage, public $intMessage, public $anotherIntMessage
    ) {
        parent::__construct($structMessage, $shortMessage);
    }
}
class MoreExtendedStruct extends ExtendedStruct {
    function __construct($f, $s, $x1, $x2, $x3, public $booleanMessage) {
        parent::__construct($f, $s, $x1, $x2, $x3);
    }
}
$s1 = new BaseStruct(new SOAPStruct("s1",1,1.1),1);
$s2 = new ExtendedStruct(new SOAPStruct("s2",2,2.2),2,"arg",-3,5);
$s3 = new MoreExtendedStruct(new SOAPStruct("s3",3,3.3),3,"arg",-3,5,true);
$client = new SoapClient(__DIR__."/round4_groupH_complex_doclit.wsdl",array("trace"=>1,"exceptions"=>0));
$client->echoMultipleFaults2(array("whichFault" => 2,
                                   "param1"     => $s1,
                                   "param2"     => $s2,
                                   "param3"     => $s3));
echo $client->__getlastrequest();
$HTTP_RAW_POST_DATA = $client->__getlastrequest();
include("round4_groupH_complex_doclit.inc");
echo "ok\n";
?>
--EXPECT--
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://soapinterop.org/types/requestresponse" xmlns:ns2="http://soapinterop.org/types"><SOAP-ENV:Body><ns1:echoMultipleFaults2Request><ns1:whichFault>2</ns1:whichFault><ns1:param1><ns2:structMessage><ns2:varString>s1</ns2:varString><ns2:varInt>1</ns2:varInt><ns2:varFloat>1.1</ns2:varFloat></ns2:structMessage><ns2:shortMessage>1</ns2:shortMessage></ns1:param1><ns1:param2><ns2:structMessage><ns2:varString>s2</ns2:varString><ns2:varInt>2</ns2:varInt><ns2:varFloat>2.2</ns2:varFloat></ns2:structMessage><ns2:shortMessage>2</ns2:shortMessage><ns2:stringMessage>arg</ns2:stringMessage><ns2:intMessage>-3</ns2:intMessage><ns2:anotherIntMessage>5</ns2:anotherIntMessage></ns1:param2><ns1:param3><ns2:structMessage><ns2:varString>s3</ns2:varString><ns2:varInt>3</ns2:varInt><ns2:varFloat>3.3</ns2:varFloat></ns2:structMessage><ns2:shortMessage>3</ns2:shortMessage><ns2:stringMessage>arg</ns2:stringMessage><ns2:intMessage>-3</ns2:intMessage><ns2:anotherIntMessage>5</ns2:anotherIntMessage><ns2:booleanMessage>true</ns2:booleanMessage></ns1:param3></ns1:echoMultipleFaults2Request></SOAP-ENV:Body></SOAP-ENV:Envelope>
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://soapinterop.org/types" xmlns:ns2="http://soapinterop.org/types/part"><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode><faultstring>Fault in response to 'echoMultipleFaults2'.</faultstring><detail><ns2:ExtendedStructPart><ns1:structMessage><ns1:varString>s2</ns1:varString><ns1:varInt>2</ns1:varInt><ns1:varFloat>2.2</ns1:varFloat></ns1:structMessage><ns1:shortMessage>2</ns1:shortMessage><ns1:stringMessage>arg</ns1:stringMessage><ns1:intMessage>-3</ns1:intMessage><ns1:anotherIntMessage>5</ns1:anotherIntMessage></ns2:ExtendedStructPart></detail></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>
ok
