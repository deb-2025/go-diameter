// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is auto-generated from our dictionaries.

package dict

import (
	"bytes"
	"fmt"
)

// Default is a Parser object with pre-loaded
// Base Protocol and Credit Control dictionaries.
var Default *Parser

func init() {
	var dictionaries = []struct{ name, xml string }{
		{"Base", baseXML},
		{"Credit Control", creditcontrolXML},
		{"Gx Charging Control", gxcreditcontrolXML},
		{"Network Access Server", networkaccessserverXML},
		{"TGPP", tgpprorfXML},
		{"TGPP_Rx", tgpprxXML},
		{"TGPP_S6a", tgpps6aXML},
		{"TGPP_Swx", tgppswxXML},
		{"TGPP_S6c", tgpps6cXML},
		{"TGPP_S13", tgpps13XML},
		{"TGPP_Cx", tgppcxXML},
		{"TGPP_Sh", tgppshXML},
	}
	var err error
	Default, err = NewParser()
	if err != nil {
		panic(err)
	}
	for _, dict := range dictionaries {
		err = Default.Load(bytes.NewReader([]byte(dict.xml)))
		if err != nil {
			panic(fmt.Sprintf("Cannot load %s dictionary: %s", dict.name, err))
		}
	}
}

var baseXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>

	<application id="0" name="Base"> <!-- Diameter Common Messages -->

		<command code="257" short="CE" name="Capabilities-Exchange">
			<request>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Host-IP-Address" required="true" min="1"/>
				<rule avp="Vendor-Id" required="true" max="1"/>
				<rule avp="Product-Name" required="true" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Supported-Vendor-Id" required="False"/>
				<rule avp="Auth-Application-Id" required="False"/>
				<rule avp="Inband-Security-Id" required="False"/>
				<rule avp="Acct-Application-Id" required="False"/>
				<rule avp="Vendor-Specific-Application-Id" required="False"/>
				<rule avp="Firmware-Revision" required="False" max="1"/>
			</request>
			<answer>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Host-IP-Address" required="true" min="1"/>
				<rule avp="Vendor-Id" required="true" max="1"/>
				<rule avp="Product-Name" required="true" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Supported-Vendor-Id" required="False"/>
				<rule avp="Auth-Application-Id" required="False"/>
				<rule avp="Inband-Security-Id" required="False"/>
				<rule avp="Acct-Application-Id" required="False"/>
				<rule avp="Vendor-Specific-Application-Id" required="False"/>
				<rule avp="Firmware-Revision" required="False" max="1"/>
			</answer>
		</command>

		<command code="258" short="RA" name="Re-Auth">
			<request>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Destination-Host" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Re-Auth-Request-Type" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="271" short="AC" name="Accounting">
			<request>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Accounting-Record-Type" required="true" max="1"/>
				<rule avp="Accounting-Record-Number" required="true" max="1"/>
				<rule avp="Acct-Application-Id" required="false" max="1"/>
				<rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="Accounting-Sub-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Interim-Interval" required="false" max="1"/>
				<rule avp="Accounting-Realtime-Required" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Event-Timestamp" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Accounting-Record-Type" required="true" max="1"/>
				<rule avp="Accounting-Record-Number" required="true" max="1"/>
				<rule avp="Acct-Application-Id" required="false" max="1"/>
				<rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Accounting-Sub-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Acct-Interim-Interval" required="false" max="1"/>
				<rule avp="Accounting-Realtime-Required" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Event-Timestamp" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="274" short="AS" name="Abort-Session">
			<request>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Destination-Host" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="275" short="ST" name="Session-Termination">
			<request>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Termination-Cause" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="280" short="DW" name="Device-Watchdog">
			<request>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
			</request>
			<answer>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
			</answer>
		</command>

		<command code="282" short="DP" name="Disconnect-Peer">
			<request>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Disconnect-Cause" required="false" max="1"/>
			</request>
			<answer>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
			</answer>
		</command>

		<avp name="Acct-Interim-Interval" code="85" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Accounting-Realtime-Required" code="483" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="1" name="DELIVER_AND_GRANT"/>
				<item code="2" name="GRANT_AND_STORE"/>
				<item code="3" name="GRANT_AND_LOSE"/>
			</data>
		</avp>

		<avp name="Acct-Multi-Session-Id" code="50" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="UTF8String"/>
		</avp>

		<avp name="Accounting-Record-Number" code="485" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Accounting-Record-Type" code="480" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="1" name="EVENT_RECORD"/>
				<item code="2" name="START_RECORD"/>
				<item code="3" name="INTERIM_RECORD"/>
				<item code="4" name="STOP_RECORD"/>
			</data>
		</avp>

		<avp name="Accounting-Session-Id" code="44" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>

		<avp name="Accounting-Sub-Session-Id" code="287" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Unsigned64"/>
		</avp>

		<avp name="Acct-Application-Id" code="259" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Auth-Application-Id" code="258" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Auth-Request-Type" code="274" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Enumerated">
				<item code="1" name="AUTHENTICATE_ONLY"/>
				<item code="2" name="AUTHORIZE_ONLY"/>
				<item code="3" name="AUTHORIZE_AUTHENTICATE"/>
			</data>
		</avp>

		<avp name="Authorization-Lifetime" code="291" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Auth-Grace-Period" code="276" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Auth-Session-State" code="277" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Enumerated">
				<item code="0" name="STATE_MAINTAINED"/>
				<item code="1" name="NO_STATE_MAINTAINED"/>
			</data>
		</avp>

		<avp name="Re-Auth-Request-Type" code="285" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Enumerated">
				<item code="0" name="AUTHORIZE_ONLY"/>
				<item code="1" name="AUTHORIZE_AUTHENTICATE"/>
			</data>
		</avp>

		<avp name="Class" code="25" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>

		<avp name="Destination-Host" code="293" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="Destination-Realm" code="283" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="Disconnect-Cause" code="273" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Enumerated">
				<item code="0" name="REBOOTING"/>
				<item code="1" name="BUSY"/>
				<item code="2" name="DO_NOT_WANT_TO_TALK_TO_YOU"/>
			</data>
		</avp>

		<avp name="Error-Message" code="281" must="-" may="P" must-not="V,M" may-encrypt="-">
			<data type="UTF8String"/>
		</avp>

		<avp name="Error-Reporting-Host" code="294" must="-" may="P" must-not="V,M" may-encrypt="-">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="Event-Timestamp" code="55" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Time"/>
		</avp>

		<avp name="Experimental-Result" code="297" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Grouped">
				<rule avp="Vendor-Id" required="true" max="1"/>
				<rule avp="Experimental-Result-Code" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Experimental-Result-Code" code="298" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Failed-AVP" code="279" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Grouped"/>
		</avp>

		<avp name="Firmware-Revision" code="267" must="-" may="-" must-not="P,V,M" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Host-IP-Address" code="257" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Address"/>
		</avp>

		<avp name="Inband-Security-Id" code="299" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Multi-Round-Time-Out" code="272" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Origin-Host" code="264" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="Origin-Realm" code="296" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="Origin-State-Id" code="278" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Product-Name" code="269" must="-" may="-" must-not="P,V,M" may-encrypt="-">
			<data type="UTF8String"/>
		</avp>

		<avp name="Proxy-Host" code="280" must="M" may="-" must-not="P,V" may-encrypt="-">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="Proxy-Info" code="284" must="M" may="-" must-not="P,V" may-encrypt="-">
			<data type="Grouped">
				<rule avp="Proxy-Host" required="true" max="1"/>
				<rule avp="Proxy-State" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Proxy-State" code="33" must="M" may="-" must-not="P,V" may-encrypt="-">
			<data type="OctetString"/>
		</avp>

		<avp name="Redirect-Host" code="292" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="DiameterURI"/>
		</avp>

		<avp name="Redirect-Host-Usage" code="261" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Enumerated">
				<item code="0" name="DONT_CACHE"/>
				<item code="1" name="ALL_SESSION"/>
				<item code="2" name="ALL_REALM"/>
				<item code="3" name="REALM_AND_APPLICATION"/>
				<item code="4" name="ALL_APPLICATION"/>
				<item code="5" name="ALL_HOST"/>
				<item code="6" name="ALL_USER"/>
			</data>
		</avp>

		<avp name="Redirect-Max-Cache-Time" code="262" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Result-Code" code="268" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Route-Record" code="282" must="M" may="-" must-not="P,V" may-encrypt="-">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="Session-Id" code="263" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="UTF8String"/>
		</avp>

		<avp name="Session-Timeout" code="27" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Session-Binding" code="270" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Session-Server-Failover" code="271" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="REFUSE_SERVICE"/>
				<item code="1" name="TRY_AGAIN"/>
				<item code="2" name="ALLOW_SERVICE"/>
				<item code="3" name="TRY_AGAIN_ALLOW_SERVICE"/>
			</data>
		</avp>

		<avp name="Supported-Vendor-Id" code="265" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Termination-Cause" code="295" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Enumerated">
				<item code="1" name="DIAMETER_LOGOUT"/>
				<item code="2" name="DIAMETER_SERVICE_NOT_PROVIDED"/>
				<item code="3" name="DIAMETER_BAD_ANSWER"/>
				<item code="4" name="DIAMETER_ADMINISTRATIVE"/>
				<item code="5" name="DIAMETER_LINK_BROKEN"/>
				<item code="6" name="DIAMETER_AUTH_EXPIRED"/>
				<item code="7" name="DIAMETER_USER_MOVED"/>
				<item code="8" name="DIAMETER_SESSION_TIMEOUT"/>
			</data>
		</avp>

		<avp name="User-Name" code="1" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="UTF8String"/>
		</avp>

		<avp name="Vendor-Id" code="266" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Vendor-Specific-Application-Id" code="260" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Grouped">
				<rule avp="Vendor-Id" required="false" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Acct-Application-Id" required="true" max="1"/>
			</data>
		</avp>

		<!-- IETF RFC 7683 - https://tools.ietf.org/html/rfc7683 -->
		<avp name="OC-Supported-Features" code="621" must-not="V">
			<data type="Grouped">
				<rule avp="OC-Feature-Vector" required="false"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="OC-Feature-Vector" code="622" must-not="V">
			<data type="Unsigned64"/>
		</avp>

		<avp name="OC-OLR" code="623" must-not="M,V">
			<data type="Grouped">
				<rule avp="OC-Sequence-Number" required="true" max="1"/>
				<rule avp="OC-Report-Type" required="true" max="1"/>
				<rule avp="OC-Reduction-Percentage" required="false" max="1"/>
				<rule avp="OC-Validity-Duration" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="OC-Sequence-Number" code="624" must-not="V">
			<data type="Unsigned64"/>
		</avp>

		<avp name="OC-Validity-Duration" code="625" must-not="V">
			<data type="Unsigned32"/>
		</avp>

		<avp name="OC-Report-Type" code="626" must-not="V">
			<data type="Enumerated">
				<item code="0" name="HOST_REPORT"/>
				<item code="1" name="REALM_REPORT"/>
			</data>
		</avp>

		<avp name="OC-Reduction-Percentage" code="627" must-not="V">
			<data type="Unsigned32"/>
		</avp>

		<!-- IETF RFC 7944 - https://tools.ietf.org/html/rfc7944 -->
		<avp name="DRMP" code="301" must-not="V">
			<data type="Enumerated">
				<item code="0" name="PRIORITY_0"/>
				<item code="1" name="PRIORITY_1"/>
				<item code="2" name="PRIORITY_2"/>
				<item code="3" name="PRIORITY_3"/>
				<item code="4" name="PRIORITY_4"/>
				<item code="5" name="PRIORITY_5"/>
				<item code="6" name="PRIORITY_6"/>
				<item code="7" name="PRIORITY_7"/>
				<item code="8" name="PRIORITY_8"/>
				<item code="9" name="PRIORITY_9"/>
				<item code="10" name="PRIORITY_10"/>
				<item code="11" name="PRIORITY_11"/>
				<item code="12" name="PRIORITY_12"/>
				<item code="13" name="PRIORITY_13"/>
				<item code="14" name="PRIORITY_14"/>
				<item code="15" name="PRIORITY_15"/>
			</data>
		</avp>


	</application>
	<application id="3" type="acct" name="Base Accounting"> <!-- Diameter Base Accounting Messages -->
	</application>
</diameter>`

var creditcontrolXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>

	<application id="4" type="auth" name="Charging Control">
		<!-- Diameter Credit Control Application -->
		<!-- http://tools.ietf.org/html/rfc4006 -->

		<command code="272" short="CC" name="Credit-Control">
			<request>
				<!-- http://tools.ietf.org/html/rfc4006#section-3.1 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Service-Context-Id" required="true" max="1"/>
				<rule avp="CC-Request-Type" required="true" max="1"/>
				<rule avp="CC-Request-Number" required="true" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="CC-Sub-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Event-Timestamp" required="false" max="1"/>
				<rule avp="Subscription-Id" required="false" max="1"/>
				<rule avp="Service-Identifier" required="false" max="1"/>
				<rule avp="Termination-Cause" required="false" max="1"/>
				<rule avp="Requested-Service-Unit" required="false" max="1"/>
				<rule avp="Requested-Action" required="false" max="1"/>
				<rule avp="Used-Service-Unit" required="false" max="1"/>
				<rule avp="Multiple-Services-Indicator" required="false" max="1"/>
				<rule avp="Multiple-Services-Credit-Control" required="false" max="1"/>
				<rule avp="Service-Parameter-Info" required="false" max="1"/>
				<rule avp="CC-Correlation-Id" required="false" max="1"/>
				<rule avp="User-Equipment-Info" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false" max="1"/>
				<rule avp="Route-Record" required="false" max="1"/>
				<rule avp="Service-Information" required="false" max="1"/>
			</request>
			<answer>
				<!-- http://tools.ietf.org/html/rfc4006#section-3.2 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="CC-Request-Type" required="true" max="1"/>
				<rule avp="CC-Request-Number" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="CC-Session-Failover" required="false" max="1"/>
				<rule avp="CC-Sub-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Event-Timestamp" required="false" max="1"/>
				<rule avp="Granted-Service-Unit" required="false" max="1"/>
				<rule avp="Multiple-Services-Credit-Control" required="false" max="1"/>
				<rule avp="Cost-Information" required="false" max="1"/>
				<rule avp="Final-Unit-Indication" required="false" max="1"/>
				<rule avp="Check-Balance-Result" required="false" max="1"/>
				<rule avp="Credit-Control-Failure-Handling" required="false" max="1"/>
				<rule avp="Direct-Debiting-Failure-Handling" required="false" max="1"/>
				<rule avp="Validity-Time" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false" max="1"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false" max="1"/>
				<rule avp="Route-Record" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
			</answer>
		</command>

		<avp name="CC-Correlation-Id" code="411" must="-" may="P,M" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.1 -->
			<data type="OctetString"/>
		</avp>

		<avp name="CC-Input-Octets" code="412" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.24 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="CC-Money" code="413" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.22 -->
			<data type="Grouped">
				<rule avp="Unit-Value" required="true" max="1"/>
				<rule avp="Currency-Code" required="true" max="1"/>
			</data>
		</avp>

		<avp name="CC-Output-Octets" code="414" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.25 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="CC-Request-Number" code="415" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.2 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="CC-Request-Type" code="416" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.3 -->
			<data type="Enumerated">
				<item code="1" name="INITIAL_REQUEST"/>
				<item code="2" name="UPDATE_REQUEST"/>
				<item code="3" name="TERMINATION_REQUEST"/>
			</data>
		</avp>

		<avp name="CC-Service-Specific-Units" code="417" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="Unsigned64"/>
		</avp>

		<avp name="CC-Session-Failover" code="418" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.4 -->
			<data type="Enumerated">
				<item code="0" name="FAILOVER_NOT_SUPPORTED"/>
				<item code="1" name="FAILOVER_SUPPORTED"/>
			</data>
		</avp>

		<avp name="CC-Sub-Session-Id" code="419" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.5 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="CC-Time" code="420" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.21 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="CC-Total-Octets" code="421" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.23 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="CC-Unit-Type" code="454" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.32 -->
			<data type="Enumerated">
				<item code="0" name="TIME"/>
				<item code="1" name="MONEY"/>
				<item code="2" name="TOTAL-OCTETS"/>
				<item code="3" name="INPUT-OCTETS"/>
				<item code="4" name="OUTPUT-OCTETS"/>
				<item code="5" name="SERVICE-SPECIFIC-UNITS"/>
			</data>
		</avp>

		<avp name="Check-Balance-Result" code="422" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.6 -->
			<data type="Enumerated">
				<item code="0" name="ENOUGH_CREDIT"/>
				<item code="1" name="NO_CREDIT"/>
			</data>
		</avp>

		<avp name="Cost-Information" code="423" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.7 -->
			<data type="Grouped">
				<rule avp="Unit-Value" required="true" max="1"/>
				<rule avp="Currency-Code" required="true" max="1"/>
				<rule avp="Cost-Unit" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Cost-Unit" code="424" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.12 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Credit-Control" code="426" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.13 -->
			<data type="Enumerated">
				<item code="0" name="CREDIT_AUTHORIZATION"/>
				<item code="1" name="RE_AUTHORIZATION"/>
			</data>
		</avp>

		<avp name="Credit-Control-Failure-Handling" code="427" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.14 -->
			<data type="Enumerated">
				<item code="0" name="TERMINATE"/>
				<item code="1" name="CONTINUE"/>
				<item code="2" name="RETRY_AND_TERMINATE"/>
			</data>
		</avp>

		<avp name="Currency-Code" code="425" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.11 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Direct-Debiting-Failure-Handling" code="428" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.15 -->
			<data type="Enumerated">
				<item code="0" name="TERMINATE_OR_BUFFER"/>
				<item code="1" name="CONTINUE"/>
			</data>
		</avp>

		<avp name="Exponent" code="429" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.9 -->
			<data type="Integer32"/>
		</avp>

		<avp name="Final-Unit-Action" code="449" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.35 -->
			<data type="Enumerated">
				<item code="0" name="TERMINATE"/>
				<item code="1" name="REDIRECT"/>
				<item code="2" name="RESTRICT_ACCESS"/>
			</data>
		</avp>

		<avp name="Final-Unit-Indication" code="430" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.34 -->
			<data type="Grouped">
				<rule avp="Final-Unit-Action" required="true" max="1"/>
				<rule avp="Restriction-Filter-Rule" required="false" max="1"/>
				<rule avp="Filter-Id" required="false" max="1"/>
				<rule avp="Redirect-Server" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Granted-Service-Unit" code="431" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.17 -->
			<data type="Grouped">
				<rule avp="Tariff-Time-Change" required="false" max="1"/>
				<rule avp="CC-Time" required="false" max="1"/>
				<rule avp="CC-Money" required="false" max="1"/>
				<rule avp="CC-Total-Octets" required="false" max="1"/>
				<rule avp="CC-Input-Octets" required="false" max="1"/>
				<rule avp="CC-Output-Octets" required="false" max="1"/>
				<rule avp="CC-Service-Specific-Units" required="false" max="1"/>
				<!-- *[ AVP ]-->
			</data>
		</avp>

		<avp name="G-S-U-Pool-Identifier" code="453" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.31 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="G-S-U-Pool-Reference" code="457" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.30 -->
			<data type="Grouped">
				<rule avp="G-S-U-Pool-Identifier" required="true" max="1"/>
				<rule avp="CC-Unit-Type" required="true" max="1"/>
				<rule avp="Unit-Value" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Multiple-Services-Credit-Control" code="456" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.16 -->
			<data type="Grouped">
				<rule avp="Granted-Service-Unit" required="false" max="1"/>
				<rule avp="Requested-Service-Unit" required="false" max="1"/>
				<rule avp="Used-Service-Unit" required="false" max="1"/>
				<rule avp="Tariff-Change-Usage" required="false" max="1"/>
				<rule avp="Service-Identifier" required="false" max="1"/>
				<rule avp="Rating-Group" required="false" max="1"/>
				<rule avp="G-S-U-Pool-Reference" required="false" max="1"/>
				<rule avp="Validity-Time" required="false" max="1"/>
				<rule avp="Result-Code" required="false" max="1"/>
				<rule avp="Final-Unit-Indication" required="false" max="1"/>
				<!-- *[ AVP ]-->
			</data>
		</avp>

		<avp name="Multiple-Services-Indicator" code="455" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.40 -->
			<data type="Enumerated">
				<item code="0" name="MULTIPLE_SERVICES_NOT_SUPPORTED"/>
				<item code="1" name="MULTIPLE_SERVICES_SUPPORTED"/>
			</data>
		</avp>

		<avp name="Rating-Group" code="432" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.29 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Redirect-Address-Type" code="433" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.38 -->
			<data type="Enumerated">
				<item code="0" name="IPv4 Address"/>
				<item code="1" name="IPv6 Address"/>
				<item code="2" name="URL"/>
				<item code="3" name="SIP URI"/>
			</data>
		</avp>

		<avp name="Redirect-Server" code="434" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.37 -->
			<data type="Grouped">
				<rule avp="Redirect-Address-Type" required="true" max="1"/>
				<rule avp="Redirect-Server-Address" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Redirect-Server-Address" code="435" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.39 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Requested-Action" code="436" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.41 -->
			<data type="Enumerated">
				<item code="0" name="DIRECT_DEBITING"/>
				<item code="1" name="REFUND_ACCOUNT"/>
				<item code="2" name="CHECK_BALANCE"/>
				<item code="3" name="PRICE_ENQUIRY"/>
			</data>
		</avp>

		<avp name="Requested-Service-Unit" code="437" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.18-->
			<data type="Grouped">
				<rule avp="CC-Time" required="false" max="1"/>
				<rule avp="CC-Money" required="false" max="1"/>
				<rule avp="CC-Total-Octets" required="false" max="1"/>
				<rule avp="CC-Input-Octets" required="false" max="1"/>
				<rule avp="CC-Output-Octets" required="false" max="1"/>
				<rule avp="CC-Service-Specific-Units" required="false" max="1"/>
				<!-- *[ AVP ]-->
			</data>
		</avp>

		<avp name="Restriction-Filter-Rule" code="438" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.36-->
			<data type="IPFilterRule"/>
		</avp>

		<avp name="Service-Context-Id" code="461" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.42-->
			<data type="UTF8String"/>
		</avp>

		<avp name="Service-Identifier" code="439" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.28-->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Service-Parameter-Info" code="440" must="-" may="P,M" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.43-->
			<data type="Grouped">
				<rule avp="Service-Parameter-Type" required="true" max="1"/>
				<rule avp="Service-Parameter-Value" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Service-Parameter-Type" code="441" must="-" may="P,M" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.44-->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Service-Parameter-Value" code="442" must="-" may="P,M" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.45-->
			<data type="OctetString"/>
		</avp>

		<avp name="Subscription-Id" code="443" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.46-->
			<data type="Grouped">
				<rule avp="Subscription-Id-Type" required="true" max="1"/>
				<rule avp="Subscription-Id-Data" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Subscription-Id-Data" code="444" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.48-->
			<data type="UTF8String"/>
		</avp>

		<avp name="Subscription-Id-Type" code="450" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.47-->
			<data type="Enumerated">
				<item code="0" name="END_USER_E164"/>
				<item code="1" name="END_USER_IMSI"/>
				<item code="2" name="END_USER_SIP_URI"/>
				<item code="3" name="END_USER_NAI"/>
			</data>
		</avp>

		<avp name="Tariff-Change-Usage" code="452" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.27-->
			<data type="Enumerated">
				<item code="0" name="UNIT_BEFORE_TARIFF_CHANGE"/>
				<item code="1" name="UNIT_AFTER_TARIFF_CHANGE"/>
				<item code="2" name="UNIT_INDETERMINATE"/>
			</data>
		</avp>

		<avp name="Tariff-Time-Change" code="451" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.20-->
			<data type="Time"/>
		</avp>

		<avp name="Unit-Value" code="445" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.8-->
			<data type="Grouped">
				<rule avp="Value-Digits" required="true" max="1"/>
				<rule avp="Exponent" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Used-Service-Unit" code="446" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.19-->
			<data type="Grouped">
				<rule avp="Tariff-Change-Usage" required="false" max="1"/>
				<rule avp="CC-Time" required="false" max="1"/>
				<rule avp="CC-Money" required="false" max="1"/>
				<rule avp="CC-Total-Octets" required="false" max="1"/>
				<rule avp="CC-Input-Octets" required="false" max="1"/>
				<rule avp="CC-Output-Octets" required="false" max="1"/>
				<rule avp="CC-Service-Specific-Units" required="false" max="1"/>
				<!-- *[ AVP ]-->
			</data>
		</avp>

		<avp name="User-Equipment-Info" code="458" must="-" may="P,M" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.49-->
			<data type="Grouped">
				<rule avp="User-Equipment-Info-Type" required="true" max="1"/>
				<rule avp="User-Equipment-Info-Value" required="true" max="1"/>
			</data>
		</avp>

		<avp name="User-Equipment-Info-Type" code="459" must="-" may="P,M" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.50-->
			<data type="Enumerated">
				<item code="0" name="IMEISV"/>
				<item code="1" name="MAC"/>
				<item code="2" name="EUI64"/>
				<item code="3" name="MODIFIED_EUI64"/>
			</data>
		</avp>

		<avp name="User-Equipment-Info-Value" code="460" must="-" may="P,M" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.51-->
			<data type="OctetString"/>
		</avp>

		<avp name="Value-Digits" code="447" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.10-->
			<data type="Integer64"/>
		</avp>

		<avp name="Validity-Time" code="448" must="M" may="P" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc4006#section-8.33-->
			<data type="Unsigned32"/>
		</avp>
	</application>
</diameter>`

var diametersyXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>

	<application id="16777302" type="auth" name="Diameter Sy">
		<!-- Diameter Credit Control Application -->
		<!-- http://tools.ietf.org/html/rfc4006 -->

		<command code="8388635" short="SL" name="Spending-Limit">
			<request>
				<!-- http://tools.ietf.org/html/rfc4006#section-3.1 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="SL-Request-Type" required="true" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Subscription-Id" required="false" max="1"/>
				<rule avp="Policy-Counter-Identifier" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false" max="1"/>
				<rule avp="Route-Record" required="false" max="1"/>
				<rule avp="Service-Information" required="false" max="1"/>
			</request>
			<answer>
				<!-- http://tools.ietf.org/html/rfc4006#section-3.2 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false" max="1"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false" max="1"/>
				<rule avp="Route-Record" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
			</answer>
		</command>

		<avp name="SL-Request-Type" code="2904" must="M" may="P" must-not="V" may-encrypt="-">
			<data type="Enumerated">
				<item code="0" name="INITIAL_REQUEST"/>
				<item code="1" name="INTERMEDIATE_REQUEST"/>
			</data>
		</avp>
		
    </application>
</diameter>`

var gxcreditcontrolXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>

    <application id="16777238" type="auth" name="Gx Charging Control">
        <!-- Diameter Gx Credit Control Application -->
        <!-- 3GPP 29.212 -->

        <vendor id="10415" name="TGPP"/>
        <command code="272" short="CC" name="Credit-Control">
            <request>
                <!-- 3GPP 29.212 Section 5.6.2 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="Auth-Application-Id" required="true" max="1"/>
                <rule avp="CC-Request-Type" required="true" max="1"/>
                <rule avp="CC-Request-Number" required="true" max="1"/>
                <rule avp="Destination-Host" required="false" max="1"/>
                <rule avp="Origin-State-Id" required="false" max="1"/>
                <rule avp="Subscription-Id" required="false" max="1"/>
                <rule avp="Termination-Cause" required="false" max="1"/>
                <rule avp="User-Equipment-Info" required="false" max="1"/>
                <rule avp="Proxy-Info" required="false" max="1"/>
                <rule avp="Route-Record" required="false" max="1"/>
                <rule avp="Framed-IP-Address" required="false" max="1"/>
                <rule avp="Framed-IPv6-Prefix" required="false"/>
                <rule avp="IP-CAN-Type" required="false" max="1"/>
                <rule avp="Called-Station-Id" required="false" max="1"/>
                <rule avp="RAT-Type" required="false" max="1"/>
                <rule avp="Network-Request-Support" required="false" max="1"/>
                <rule avp="Default-EPS-Bearer-QoS" required="false" max="1"/>
                <rule avp="AN-GW-Address" required="false" max="2"/>
                <rule avp="Bearer-Usage" required="false" max="1"/>
                <rule avp="Online" required="false" max="1"/>
                <rule avp="Offline" required="false" max="1"/>
                <rule avp="Access-Network-Charging-Identifier-Gx" required="false"/>
                <rule avp="TGPP-SGSN-Address" required="false" max="1"/>
                <rule avp="TGPP-GGSN-Address" required="false" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="Access-Network-Charging-Address" required="false" max="1"/>
                <rule avp="TGPP-MS-TimeZone" required="false" max="1"/>
                <rule avp="TGPP-Selection-Mode" required="false" max="1"/>
                <rule avp="QoS-Information" required="false" max="1"/>
                <rule avp="TGPP-SGSN-MCC-MNC" required="false" max="1"/>
                <rule avp="TGPP-User-Location-Info" required="false" max="1"/>
            </request>
            <answer>
                <!-- 3GPP 29.212 Section 5.6.3 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Result-Code" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="CC-Request-Type" required="true" max="1"/>
                <rule avp="CC-Request-Number" required="true" max="1"/>
                <rule avp="Origin-State-Id" required="false" max="1"/>
                <rule avp="Proxy-Info" required="false" max="1"/>
                <rule avp="Route-Record" required="false" max="1"/>
                <rule avp="Failed-AVP" required="false" max="1"/>
                <rule avp="Charging-Rule-Install" required="false"/>
                <rule avp="Charging-Rule-Remove" required="false"/>
                <rule avp="Usage-Monitoring-Information" required="false"/>
                <rule avp="Event-Trigger" required="false"/>
                <rule avp="Revalidation-Time" required="false"/>
            </answer>
        </command>

        <command code="258" short="RA" name="Re-Auth">
            <request>
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="Destination-Host" required="true" max="1"/>
                <rule avp="Auth-Application-Id" required="true" max="1"/>
                <rule avp="Re-Auth-Request-Type" required="true" max="1"/>
                <rule avp="QoS-Information" required="false" max="1"/>
                <rule avp="Origin-State-Id" required="false" max="1"/>
                <rule avp="Proxy-Info" required="false"/>
                <rule avp="Route-Record" required="false"/>
                <rule avp="Event-Trigger" required="false"/>
                <rule avp="Revalidation-Time" required="false"/>
            </request>
            <answer>
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Result-Code" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Origin-State-Id" required="false" max="1"/>
                <rule avp="Error-Message" required="false" max="1"/>
                <rule avp="Error-Reporting-Host" required="false" max="1"/>
                <rule avp="Failed-AVP" required="false" max="1"/>
                <rule avp="Proxy-Info" required="false"/>
            </answer>
        </command>

        <avp name="Flow-Description" code="507" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="IPFilterRule"/>
        </avp>


        <avp name="Charging-Rule-Install" code="1001" must="M,V" may="P" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.2 -->
            <data type="Grouped">
                <rule avp="Charging-Rule-Name" required="false"/>
                <rule avp="Charging-Rule-Base-Name" required="false"/>
                <rule avp="Charging-Rule-Definition" required="false"/>
                <rule avp="Rule-Activation-Time" required="false"/>
                <rule avp="Rule-Deactivation-Time" required="false"/>
                <!-- *[ AVP ]-->
            </data>
        </avp>

        <avp name="Charging-Rule-Remove" code="1002" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.3 -->
            <data type="Grouped">
                <rule avp="Charging-Rule-Name" required="false"/>
                <rule avp="Charging-Rule-Base-Name" required="false"/>
                <!-- *[ AVP ]-->
            </data>
        </avp>

        <avp name="Charging-Rule-Definition" code="1003" must="M,V" may="P" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Grouped">
                <rule avp="Charging-Rule-Name" required="true" max="1"/>
                <rule avp="Rating-Group" required="false" max="1"/>
                <rule avp="Service-Identifier" required="false" max="1"/>
                <rule avp="Flow-Information" required="false"/>
                <rule avp="Flow-Description" required="false"/>
                <rule avp="Precedence" required="false" max="1"/>
                <rule avp="Monitoring-Key" required="false" max="1"/>
                <rule avp="Redirect-Information" required="false" max="1"/>
                <!-- *[ AVP ]-->
            </data>
        </avp>

        <avp name="Charging-Rule-Base-Name" code="1004" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.6 -->
            <data type="UTF8String"/>
        </avp>

        <avp name="Charging-Rule-Name" code="1005" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.6 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Event-Trigger" code="1006" must="M,V" map="P" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.7 -->
            <data type="Enumerated">
                <item code="0" name="SGSN_CHANGE"/>
                <item code="1" name="QOS_CHANGE"/>
                <item code="2" name="RAT_CHANGE"/>
                <item code="3" name="TFT_CHANGE"/>
                <item code="4" name="PLMN_CHANGE"/>
                <item code="5" name="LOSS_OF_BEARER"/>
                <item code="6" name="RECOVERY_OF_BEARER"/>
                <item code="7" name="IP-CAN_CHANGE"/>
                <item code="11" name="QOS_CHANGE_EXCEEDING_AUTHORIZATION"/>
                <item code="12" name="RAI_CHANGE"/>
                <item code="13" name="USER_LOCATION_CHANGE"/>
                <item code="14" name="NO_EVENT_TRIGGERS"/>
                <item code="15" name="OUT_OF_CREDIT"/>
                <item code="16" name="REALLOCATION_OF_CREDIT"/>
                <item code="17" name="REVALIDATION_TIMEOUT"/>
                <item code="18" name="UE_IP_ADDRESS_ALLOCATE"/>
                <item code="19" name="UE_IP_ADDRESS_RELEASE"/>
                <item code="20" name="DEFAULT_EPS_BEARER_QOS_CHANGE"/>
                <item code="21" name="AN_GW_CHANGE"/>
                <item code="22" name="SUCCESSFUL_RESOURCE_ALLOCATION"/>
                <item code="23" name="RESOURCE_MODIFICATION_REQUEST"/>
                <item code="24" name="PGW_TRACE_CONTROL"/>
                <item code="25" name="UE_TIME_ZONE_CHANGE"/>
                <item code="26" name="TAI_CHANGE"/>
                <item code="27" name="ECGI_CHANGE"/>
                <item code="28" name="CHARGING_CORRELATION_EXCHANGE"/>
                <item code="29" name="APN-AMBR_MODIFICATION_FAILURE"/>
                <item code="30" name="USER_CSG_INFORMATION_CHANGE"/>
                <item code="33" name="USAGE_REPORT"/>
            </data>
        </avp>

        <avp name="Revalidation-Time" code="1042" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212  Section 5.3.41 -->
            <data type="Time"/>
        </avp>

        <avp name="Precedence" code="1010" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Unsigned32"/>
        </avp>

        <avp name="ToS-Traffic-Class" code="1014" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.15 -->
            <data type="Unsigned32"/>
        </avp>

        <avp name="IP-CAN-Type" code="1027" must="M,V" map="P" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.27 -->
            <data type="Enumerated">
                <item code="0" name="3GPP-GPRS"/>
                <item code="1" name="DOCSIS"/>
                <item code="2" name="xDSL"/>
                <item code="3" name="WiMAX"/>
                <item code="4" name="3GPP2"/>
                <item code="5" name="3GPP-EPS"/>
                <item code="6" name="Non-3GPP-EPS"/>
                <item code="7" name="FBA"/>
                <item code="8" name="3GPP-5GS"/>
                <item code="9" name="Non-3GPP-5GS"/>
            </data>
        </avp>

        <avp name="Rule-Activation-Time" code="1043" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Time"/>
        </avp>

        <avp name="Rule-Deactivation-Time" code="1044" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Time"/>
        </avp>

        <avp name="Security-Parameter-Index" code="1056" must="V" must-not="M" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.51 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Flow-Label" code="1057" must="V" must-not="M" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.52 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Flow-Information" code="1058" must="V" must-not="M" may="P" may-encryp="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.53 -->
            <data type="Grouped">
                <rule avp="Flow-Description" required="false" max="1"/>
                <rule avp="Packet-Filter-Identifier" required="false" max="1"/>
                <rule avp="Packet-Filter-Usage" required="false" max="1"/>
                <rule avp="ToS-Traffic-Class" required="false" max="1"/>
                <rule avp="Security-Parameter-Index" required="false" max="1"/>
                <rule avp="Flow-Label" required="false" max="1"/>
                <rule avp="Flow-Direction" required="false" max="1"/>
            </data>
        </avp>

        <avp name="Packet-Filter-Identifier" code="1060" must="V" must-not="M" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.55 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Monitoring-Key" code="1066" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Usage-Monitoring-Information" code="1067" must="V" may="P" must-not="M,V" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Grouped">
                <rule avp="Monitoring-Key" required="false" max="1"/>
                <rule avp="Granted-Service-Unit" required="false" max="2"/>
                <rule avp="Used-Service-Unit" required="false" max="2"/>
                <rule avp="Usage-Monitoring-Level" required="false" max="1"/>
                <rule avp="Usage-Monitoring-Report" required="false" max="1"/>
                <rule avp="Usage-Monitoring-Support" required="false" max="1"/>
            </data>
        </avp>

        <avp name="Usage-Monitoring-Level" code="1068" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Enumerated">
                <item code="0" name="SESSION_LEVEL"/>
                <item code="1" name="PCC_RULE_LEVEL"/>
            </data>
        </avp>

        <avp name="Usage-Monitoring-Report" code="1069" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Enumerated">
                <item code="0" name="USAGE_MONITORING_REPORT"/>
            </data>
        </avp>

        <avp name="Usage-Monitoring-Support" code="1070" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 -->
            <data type="Enumerated">
                <item code="0" name="USAGE_MONITORING_SUPPORT"/>
            </data>
        </avp>

        <avp name="Packet-Filter-Usage" code="1072" must="V" must-not="M" map="P" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.66 -->
            <data type="Enumerated">
                <item code="1" name="SEND_TO_UE"/>
            </data>
        </avp>

        <avp name="Flow-Direction" code="1080" must="V" must-not="M" map="P" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.65 -->
            <data type="Enumerated">
                <item code="0" name="UNSPECIFIED"/>
                <item code="1" name="DOWNLINK"/>
                <item code="2" name="UPLINK"/>
                <item code="3" name="BIDIRECTIONAL"/>
            </data>
        </avp>

        <avp name="Redirect-Information" code="1085" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.82 -->
            <data type="Grouped">
                <rule avp="Redirect-Support" required="true" max="1"/>
                <rule avp="Redirect-Address-Type" required="false" max="1"/>
                <rule avp="Redirect-Server-Address" required="false" max="1"/>
                <!-- *[ AVP ]-->
            </data>
        </avp>

        <avp name="Redirect-Support" code="1086" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.83 -->
            <data type="Enumerated">
                <item code="0" name="REDIRECTION_DISABLED"/>
                <item code="1" name="REDIRECTION_ENABLED"/>
            </data>
        </avp>

        <avp name="Network-Request-Support" code="1024" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.24 -->
            <data type="Enumerated">
                <item code="0" name="NETWORK_REQUEST_NOT_SUPPORTED"/>
                <item code="1" name="NETWORK_REQUEST_SUPPORTED"/>
            </data>
        </avp>

        <avp name="Offline" code="1008" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.9 -->
            <data type="Enumerated">
                <item code="0" name="DISABLE_OFFLINE"/>
                <item code="1" name="ENABLE_OFFLINE"/>
            </data>
        </avp>

        <avp name="Online" code="1009" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.10 -->
            <data type="Enumerated">
                <item code="0" name="DISABLE_ONLINE"/>
                <item code="1" name="ENABLE_ONLINE"/>
            </data>
        </avp>

        <avp name="Default-EPS-Bearer-QoS" code="1049" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.48 -->
            <data type="Grouped">
                <rule avp="QoS-Class-Identifier" required="false" max="1"/>
                <rule avp="Allocation-Retention-Priority" required="false" max="1"/>
                <!-- *[ AVP ]-->
            </data>
        </avp>

        <avp name="AN-GW-Address" code="1050" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.49 -->
            <data type="Address"/>
        </avp>

        <avp name="Bearer-Usage" code="1000" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.1 -->
            <data type="Enumerated">
                <item code="0" name="GENERAL"/>
                <item code="1" name="IMS_SIGNALLING"/>
            </data>
        </avp>

        <avp name="Access-Network-Charging-Identifier-Gx" code="1022" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 Section 5.3.22 -->
            <data type="Grouped">
                <rule avp="Access-Network-Charging-Identifier-Value" required="true" max="1"/>
                <rule avp="Charging-Rule-Base-Name" required="false"/>
                <rule avp="Charging-Rule-Name" required="false"/>
                <!-- *[ AVP ]-->
            </data>
        </avp>

        <avp name="TGPP-SGSN-Address" code="6" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.061 Table 9a -->
            <data type="OctetString"/>
        </avp>

        <avp name="TGPP-GGSN-Address" code="7" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.061 Table 9a -->
            <data type="OctetString"/>
        </avp>

        <avp name="Access-Network-Charging-Address" code="501" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP TS 29.214 Section 5.3.2 -->
            <data type="Address"/>
        </avp>

        <avp name="TGPP-MS-TimeZone" code="23" must="V" may="P" must-not="M" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.061 Table 9a -->
            <data type="OctetString"/>
        </avp>

        <avp name="TFT-Filter" code="1012" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 5.3.13-->
            <data type="IPFilterRule"/>
        </avp>

        <avp name="TFT-Packet-Filter-Information" code="1013" must="M,V" may="P" may-encrypt="y" vendor-id="10415">
            <!-- 3GPP 29.212 5.3.14-->
            <data type="Grouped">
                <rule avp="Precedence" required="false" max="1"/>
                <rule avp="TFT-Filter" required="false" max="1"/>
                <rule avp="ToS-Traffic-Class" required="false" max="1"/>
                <rule avp="Security-Parameter-Index" required="false" max="1"/>
                <rule avp="Flow-Label" required="false" max="1"/>
                <rule avp="Flow-Direction" required="false" max="1"/>
                <!-- *[ AVP ]-->
            </data>
        </avp>

    </application>
</diameter>`

var networkaccessserverXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>

	<application id="1" type="auth" name="Network Access">
		<!-- Diameter Network Access Server Application -->
		<!-- http://tools.ietf.org/html/rfc7155 -->

		<command code="265" short="AA" name="AA">
			<request>
				<!-- https://tools.ietf.org/html/rfc7155#section-3.1 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Auth-Request-Type" required="true" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="NAS-Identifier" required="false" max="1"/>
				<rule avp="NAS-IP-Address" required="true" max="1"/>
				<rule avp="NAS-IPv6-Address" required="false" max="1"/>
				<rule avp="NAS-Port" required="false" max="1"/>
				<rule avp="NAS-Port-Id" required="false" max="1"/>
				<rule avp="NAS-Port-Type" required="false" max="1"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Port-Limit" required="false" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="User-Password" required="false" max="1"/>
				<rule avp="Service-Type" required="false" max="1"/>
				<rule avp="State" required="false" max="1"/>
				<rule avp="Authorization-Lifetime" required="false" max="1"/>
				<rule avp="Auth-Grace-Period" required="false" max="1"/>
				<rule avp="Auth-Session-State" required="false" max="1"/>
				<rule avp="Callback-Number" required="false" max="1"/>
				<rule avp="Called-Station-Id" required="false" max="1"/>
				<rule avp="Calling-Station-Id" required="false" max="1"/>
				<rule avp="Originating-Line-Info" required="false" max="1"/>
				<rule avp="Connect-Info" required="false" max="1"/>
				<rule avp="CHAP-Auth" required="false" max="1"/>
				<rule avp="CHAP-Challenge" required="false" max="1"/>
				<rule avp="Framed-Compression" required="false"/>
				<rule avp="Framed-Interface-Id" required="false" max="1"/>
				<rule avp="Framed-IP-Address" required="false" max="1"/>
				<rule avp="Framed-IPv6-Prefix" required="false"/>
				<rule avp="Framed-IP-Netmask" required="false" max="1"/>
				<rule avp="Framed-MTU" required="false" max="1"/>
				<rule avp="Framed-Protocol" required="false" max="1"/>
				<rule avp="ARAP-Password" required="false" max="1"/>
				<rule avp="ARAP-Security" required="false" max="1"/>
				<rule avp="ARAP-Security-Data" required="false"/>
				<rule avp="Login-IP-Host" required="false"/>
				<rule avp="Login-IPv6-Host" required="false"/>
				<rule avp="Login-LAT-Group" required="false" max="1"/>
				<rule avp="Login-LAT-Node" required="false" max="1"/>
				<rule avp="Login-LAT-Port" required="false" max="1"/>
				<rule avp="Login-LAT-Service" required="false" max="1"/>
				<rule avp="Tunneling" required="false"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.2 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Auth-Request-Type" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Service-Type" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Configuration-Token" required="false"/>
				<rule avp="Acct-Interim-Interval" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false"/>
				<rule avp="Idle-Timeout" required="false" max="1"/>
				<rule avp="Authorization-Lifetime" required="false" max="1"/>
				<rule avp="Auth-Grace-Period" required="false" max="1"/>
				<rule avp="Auth-Session-State" required="false" max="1"/>
				<rule avp="Re-Auth-Request-Type" required="false" max="1"/>
				<rule avp="Multi-Round-Time-Out" required="false" max="1"/>
				<rule avp="Session-Timeout" required="false" max="1"/>
				<rule avp="State" required="false" max="1"/>
				<rule avp="Reply-Message" required="false"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Filter-Id" required="false"/>
				<rule avp="Password-Retry" required="false" max="1"/>
				<rule avp="Port-Limit" required="false" max="1"/>
				<rule avp="Prompt" required="false" max="1"/>
				<rule avp="ARAP-Challenge-Response" required="false" max="1"/>
				<rule avp="ARAP-Features" required="false" max="1"/>
				<rule avp="ARAP-Security" required="false" max="1"/>
				<rule avp="ARAP-Security-Data" required="false"/>
				<rule avp="ARAP-Zone-Access" required="false" max="1"/>
				<rule avp="Callback-Id" required="false" max="1"/>
				<rule avp="Callback-Number" required="false" max="1"/>
				<rule avp="Framed-Appletalk-Link" required="false" max="1"/>
				<rule avp="Framed-Appletalk-Network" required="false"/>
				<rule avp="Framed-Appletalk-Zone" required="false" max="1"/>
				<rule avp="Framed-Compression" required="false"/>
				<rule avp="Framed-Interface-Id" required="false" max="1"/>
				<rule avp="Framed-IP-Address" required="false" max="1"/>
				<rule avp="Framed-IPv6-Prefix" required="false"/>
				<rule avp="Framed-IPv6-Pool" required="false" max="1"/>
				<rule avp="Framed-IPv6-Route" required="false"/>
				<rule avp="Framed-IP-Netmask" required="false" max="1"/>
				<rule avp="Framed-Route" required="false"/>
				<rule avp="Framed-Pool" required="false" max="1"/>
				<rule avp="Framed-IPX-Network" required="false" max="1"/>
				<rule avp="Framed-MTU" required="false" max="1"/>
				<rule avp="Framed-Protocol" required="false" max="1"/>
				<rule avp="Framed-Routing" required="false" max="1"/>
				<rule avp="Login-IP-Host" required="false"/>
				<rule avp="Login-IPv6-Host" required="false"/>
				<rule avp="Login-LAT-Group" required="false" max="1"/>
				<rule avp="Login-LAT-Node" required="false" max="1"/>
				<rule avp="Login-LAT-Port" required="false" max="1"/>
				<rule avp="Login-LAT-Service" required="false" max="1"/>
				<rule avp="Login-Service" required="false" max="1"/>
				<rule avp="Login-TCP-Port" required="false" max="1"/>
				<rule avp="NAS-Filter-Rule" required="false"/>
				<rule avp="QoS-Filter-Rule" required="false"/>
				<rule avp="Tunneling" required="false"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="258" short="RA" name="Re-Auth">
			<request>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.3 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Destination-Host" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Re-Auth-Request-Type" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="NAS-Identifier" required="false" max="1"/>
				<rule avp="NAS-IP-Address" required="true" max="1"/>
				<rule avp="NAS-IPv6-Address" required="false" max="1"/>
				<rule avp="NAS-Port" required="false" max="1"/>
				<rule avp="NAS-Port-Id" required="false" max="1"/>
				<rule avp="NAS-Port-Type" required="false" max="1"/>
				<rule avp="Service-Type" required="false" max="1"/>
				<rule avp="Framed-IP-Address" required="false" max="1"/>
				<rule avp="Framed-IPv6-Prefix" required="false" max="1"/>
				<rule avp="Framed-Interface-Id" required="false" max="1"/>
				<rule avp="Called-Station-Id" required="false" max="1"/>
				<rule avp="Calling-Station-Id" required="false" max="1"/>
				<rule avp="Originating-Line-Info" required="false" max="1"/>
				<rule avp="Acct-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="State" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Reply-Message" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.4 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Service-Type" required="false" max="1"/>
				<rule avp="Configuration-Token" required="false"/>
				<rule avp="Idle-Timeout" required="false" max="1"/>
				<rule avp="Authorization-Lifetime" required="false" max="1"/>
				<rule avp="Auth-Grace-Period" required="false" max="1"/>
				<rule avp="Re-Auth-Request-Type" required="false" max="1"/>
				<rule avp="State" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Reply-Message" required="false"/>
				<rule avp="Prompt" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="275" short="ST" name="Session-Termination">
			<request>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.5 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Termination-Cause" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.6 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="274" short="AS" name="Abort-Session">
			<request>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.7 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Destination-Host" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="NAS-Identifier" required="false" max="1"/>
				<rule avp="NAS-IP-Address" required="true" max="1"/>
				<rule avp="NAS-IPv6-Address" required="false" max="1"/>
				<rule avp="NAS-Port" required="false" max="1"/>
				<rule avp="NAS-Port-Id" required="false" max="1"/>
				<rule avp="NAS-Port-Type" required="false" max="1"/>
				<rule avp="Service-Type" required="false" max="1"/>
				<rule avp="Framed-IP-Address" required="false" max="1"/>
				<rule avp="Framed-IPv6-Prefix" required="false" max="1"/>
				<rule avp="Framed-Interface-Id" required="false" max="1"/>
				<rule avp="Called-Station-Id" required="false" max="1"/>
				<rule avp="Calling-Station-Id" required="false" max="1"/>
				<rule avp="Originating-Line-Info" required="false" max="1"/>
				<rule avp="Acct-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="State" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Reply-Message" required="false"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.8 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="State" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>

		<command code="271" short="AC" name="Accounting">
			<request>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.9 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Accounting-Record-Type" required="true" max="1"/>
				<rule avp="Accounting-Record-Number" required="true" max="1"/>
				<rule avp="Acct-Application-Id" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Accounting-Sub-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="Event-Timestamp" required="false" max="1"/>
				<rule avp="Acct-Delay-Time" required="false" max="1"/>
				<rule avp="NAS-Identifier" required="false" max="1"/>
				<rule avp="NAS-IP-Address" required="true" max="1"/>
				<rule avp="NAS-IPv6-Address" required="false" max="1"/>
				<rule avp="NAS-Port" required="false" max="1"/>
				<rule avp="NAS-Port-Id" required="false" max="1"/>
				<rule avp="NAS-Port-Type" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Service-Type" required="false" max="1"/>
				<rule avp="Termination-Cause" required="false" max="1"/>
				<rule avp="Accounting-Input-Octets" required="false" max="1"/>
				<rule avp="Accounting-Input-Packets" required="false" max="1"/>
				<rule avp="Accounting-Output-Octets" required="false" max="1"/>
				<rule avp="Accounting-Output-Packets" required="false" max="1"/>
				<rule avp="Acct-Authentic" required="false" max="1"/>
				<rule avp="Accounting-Auth-Method" required="false" max="1"/>
				<rule avp="Acct-Link-Count" required="false" max="1"/>
				<rule avp="Acct-Session-Time" required="false" max="1"/>
				<rule avp="Acct-Tunnel-Connection" required="false" max="1"/>
				<rule avp="Acct-Tunnel-Packets-Lost" required="false" max="1"/>
				<rule avp="Callback-Id" required="false" max="1"/>
				<rule avp="Callback-Number" required="false" max="1"/>
				<rule avp="Called-Station-Id" required="false" max="1"/>
				<rule avp="Calling-Station-Id" required="false" max="1"/>
				<rule avp="Connection-Info" required="false"/>
				<rule avp="Originating-Line-Info" required="false" max="1"/>
				<rule avp="Authorization-Lifetime" required="false" max="1"/>
				<rule avp="Session-Timeout" required="false" max="1"/>
				<rule avp="Idle-Timeout" required="false" max="1"/>
				<rule avp="Port-Limit" required="false" max="1"/>
				<rule avp="Accounting-Realtime-Required" required="false" max="1"/>
				<rule avp="Acct-Interim-Interval" required="false" max="1"/>
				<rule avp="Filter-Id" required="false"/>
				<rule avp="NAS-Filter-Rule" required="false"/>
				<rule avp="QoS-Filter-Rule" required="false"/>
				<rule avp="Framed-Appletalk-Link" required="false" max="1"/>
				<rule avp="Framed-Appletalk-Network" required="false" max="1"/>
				<rule avp="Framed-Appletalk-Zone" required="false" max="1"/>
				<rule avp="Framed-Compression" required="false" max="1"/>
				<rule avp="Framed-Interface-Id" required="false" max="1"/>
				<rule avp="Framed-IP-Address" required="false" max="1"/>
				<rule avp="Framed-IP-Netmask" required="false" max="1"/>
				<rule avp="Framed-IPv6-Prefix" required="false"/>
				<rule avp="Framed-IPv6-Pool" required="false" max="1"/>
				<rule avp="Framed-IPv6-Route" required="false"/>
				<rule avp="Framed-IPX-Network" required="false" max="1"/>
				<rule avp="Framed-MTU" required="false" max="1"/>
				<rule avp="Framed-Pool" required="false" max="1"/>
				<rule avp="Framed-Protocol" required="false" max="1"/>
				<rule avp="Framed-Route" required="false"/>
				<rule avp="Framed-Routing" required="false" max="1"/>
				<rule avp="Login-IP-Host" required="false"/>
				<rule avp="Login-IPv6-Host" required="false"/>
				<rule avp="Login-LAT-Group" required="false" max="1"/>
				<rule avp="Login-LAT-Node" required="false" max="1"/>
				<rule avp="Login-LAT-Port" required="false" max="1"/>
				<rule avp="Login-LAT-Service" required="false" max="1"/>
				<rule avp="Login-Service" required="false" max="1"/>
				<rule avp="Login-TCP-Port" required="false" max="1"/>
				<rule avp="Tunneling" required="false"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
			</request>
			<answer>
				<!-- http://tools.ietf.org/html/rfc7155#section-3.10 -->
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="Result-Code" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Accounting-Record-Type" required="true" max="1"/>
				<rule avp="Accounting-Record-Number" required="true" max="1"/>
				<rule avp="Acct-Application-Id" required="true" max="1"/>
				<rule avp="User-Name" required="false" max="1"/>
				<rule avp="Accounting-Sub-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Session-Id" required="false" max="1"/>
				<rule avp="Acct-Multi-Session-Id" required="false" max="1"/>
				<rule avp="Event-Timestamp" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false"/>
				<rule avp="Origin-AAA-Protocol" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="NAS-Identifier" required="false" max="1"/>
				<rule avp="NAS-IP-Address" required="true" max="1"/>
				<rule avp="NAS-IPv6-Address" required="false" max="1"/>
				<rule avp="NAS-Port" required="false" max="1"/>
				<rule avp="NAS-Port-Id" required="false" max="1"/>
				<rule avp="NAS-Port-Type" required="false" max="1"/>
				<rule avp="Service-Type" required="false" max="1"/>
				<rule avp="Termination-Cause" required="false" max="1"/>
				<rule avp="Accounting-Realtime-Required" required="false" max="1"/>
				<rule avp="Acct-Interim-Interval" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Proxy-Info" required="false"/>
			</answer>
		</command>



		<avp name="NAS-Port" code="5" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.2 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="NAS-Port-Id" code="87" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.3 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="NAS-Port-Type" code="61" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.4 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-13 -->
				<item code="0" name="Async"/>
				<item code="1" name="Sync"/>
				<item code="2" name="ISDN Sync"/>
				<item code="3" name="ISDN Async V.120"/>
				<item code="4" name="ISDN Async V.110"/>
				<item code="5" name="Virtual"/>
				<item code="6" name="PIAFS"/>
				<item code="7" name="HDLC Clear Channel"/>
				<item code="8" name="X.25"/>
				<item code="9" name="X.75"/>
				<item code="10" name="G.3 Fax"/>
				<item code="11" name="SDSL - Symmetric DSL"/>
				<item code="12" name="ADSL-CAP - Asymmetric DSL, Carrierless Amplitude Phase Modulation"/>
				<item code="13" name="ADSL-DMT - Asymmetric DSL, Discrete Multi-Tone"/>
				<item code="14" name="IDSL - ISDN Digital Subscriber Line"/>
				<item code="15" name="Ethernet"/>
				<item code="16" name="xDSL - Digital Subscriber Line of unknown type"/>
				<item code="17" name="Cable"/>
				<item code="18" name="Wireless - Other"/>
				<item code="19" name="Wireless - IEEE 802.11"/>
				<item code="20" name="Token-Ring"/>
				<item code="21" name="FDDI"/>
				<item code="22" name="Wireless - CDMA2000"/>
				<item code="23" name="Wireless - UMTS"/>
				<item code="24" name="Wireless - 1X-EV"/>
				<item code="25" name="IAPP"/>
				<item code="26" name="FTTP - Fiber to the Premises"/>
				<item code="27" name="Wireless - IEEE 802.16"/>
				<item code="28" name="Wireless - IEEE 802.20"/>
				<item code="29" name="Wireless - IEEE 802.22"/>
				<item code="30" name="PPPoA - PPP over ATM"/>
				<item code="31" name="PPPoEoA - PPP over Ethernet over ATM"/>
				<item code="32" name="PPPoEoE - PPP over Ethernet over Ethernet"/>
				<item code="33" name="PPPoEoVLAN - PPP over Ethernet over VLAN"/>
				<item code="34" name="PPPoEoQinQ - PPP over Ethernet over IEEE 802.1QinQ"/>
				<item code="35" name="xPON - Passive Optical Network"/>
				<item code="36" name="Wireless - XGP"/>
				<item code="37" name="WiMAX Pre-Release 8 IWK Function"/>
				<item code="38" name="WIMAX-WIFI-IWK: WiMAX WIFI Interworking"/>
				<item code="39" name="WIMAX-SFF: Signaling Forwarding Function for LTE/3GPP2"/>
				<item code="40" name="WIMAX-HA-LMA: WiMAX HA and or LMA function"/>
				<item code="41" name="WIMAX-DHCP: WIMAX DCHP service"/>
				<item code="42" name="WIMAX-LBS: WiMAX location based service"/>
				<item code="43" name="WIMAX-WVS: WiMAX voice service"/>
			</data>
		</avp>

		<avp name="Called-Station-Id" code="30" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.5 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Calling-Station-Id" code="31" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.6 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Connect-Info" code="77" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.7 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Originating-Line-Info" code="94" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.8 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Reply-Message" code="18" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.2.9 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="User-Password" code="2" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.1 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Password-Retry" code="75" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.2 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Prompt" code="76" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.3 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-17 -->
				<item code="0" name="No Echo"/>
				<item code="1" name="Echo"/>
			</data>
		</avp>

		<avp name="CHAP-Auth" code="402" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.4 -->
			<data type="Grouped">
				<rule avp="CHAP-Algorithm" required="true" max="1"/>
				<rule avp="CHAP-Ident" required="true" max="1"/>
				<rule avp="CHAP-Response" required="true" max="1"/>
			</data>
		</avp>


		<avp name="CHAP-Algorithm" code="403" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.5 -->
			<data type="Enumerated">
				<item code="5" name="CHAP with MD5"/>
			</data>
		</avp>

		<avp name="CHAP-Ident" code="404" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.6 -->
			<data type="OctetString"/>
		</avp>

		<avp name="CHAP-Response" code="405" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.7 -->
			<data type="OctetString"/>
		</avp>

		<avp name="CHAP-Challenge" code="60" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.8 -->
			<data type="OctetString"/>
		</avp>

		<avp name="ARAP-Password" code="70" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.9 -->
			<data type="OctetString"/>
		</avp>

		<avp name="ARAP-Challenge-Response" code="84" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.10 -->
			<data type="OctetString"/>
		</avp>

		<avp name="ARAP-Security" code="73" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.11 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="ARAP-Security-Data" code="74" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.3.12 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Service-Type" code="6" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.1 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-4 -->
				<item code="1" name="Login"/>
				<item code="2" name="Framed"/>
				<item code="3" name="Callback Login"/>
				<item code="4" name="Callback Framed"/>
				<item code="5" name="Outbound"/>
				<item code="6" name="Administrative"/>
				<item code="7" name="NAS Prompt"/>
				<item code="8" name="Authenticate Only"/>
				<item code="9" name="Callback NAS Prompt"/>
				<item code="10" name="Call Check"/>
				<item code="11" name="Callback Administrative"/>
				<item code="12" name="Voice"/>
				<item code="13" name="Fax"/>
				<item code="14" name="Modem Relay"/>
				<item code="15" name="IAPP-Register"/>
				<item code="16" name="IAPP-AP-Check"/>
				<item code="17" name="Authorize Only"/>
				<item code="18" name="Framed-Management"/>
				<item code="19" name="Additional-Authorization"/>
			</data>
		</avp>

		<avp name="Callback-Number" code="19" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.2 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Callback-Id" code="20" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.3 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Idle-Timeout" code="28" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.4 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Port-Limit" code="62" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.5 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="NAS-Filter-Rule" code="400" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.6 -->
			<data type="IPFilterRule"/>
		</avp>

		<avp name="Filter-Id" code="11" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.7 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Configuration-Token" code="78" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.8 -->
			<data type="OctetString"/>
		</avp>

		<!--avp name="QoS-Filter-Rule" code="407" must="-" may="" must-not="-" may-encrypt="Y"-->
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.9 -->
			<!--data type="QoSFilterRule"/-->
		<!--/avp-->


		<avp name="Framed-Protocol" code="7" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.1 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-5 -->
				<item code="1" name="PPP"/>
				<item code="2" name="SLIP"/>
				<item code="3" name="AppleTalk Remote Access Protocol (ARAP)"/>
				<item code="4" name="Gandalf proprietary SingleLink/MultiLink protocol	"/>
				<item code="5" name="Xylogics proprietary IPX/SLIP"/>
				<item code="6" name="X.75 Synchronous"/>
				<item code="7" name="GPRS PDP Context"/>
			</data>
		</avp>

		<avp name="Framed-Routing" code="10" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.2 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-6 -->
				<item code="0" name="None"/>
				<item code="1" name="Send routing packets"/>
				<item code="2" name="Listen for routing packets"/>
				<item code="3" name="Send and Listen"/>
			</data>
		</avp>

		<avp name="Framed-MTU" code="12" must="M" may="" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.3 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Framed-Compression" code="13" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.4 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-7 -->
				<item code="0" name="None"/>
				<item code="1" name="VJ TCP/IP header compression	"/>
				<item code="2" name="IPX header compression"/>
				<item code="3" name="Stac-LZS compression"/>
			</data>
		</avp>

		<avp name="Framed-IP-Address" code="8" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.1 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Framed-IP-Netmask" code="9" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.2 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Framed-Route" code="22" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.3 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Framed-Pool" code="88" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.4 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Framed-Interface-Id" code="96" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.5 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="Framed-IPv6-Prefix" code="97" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.6 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Framed-IPv6-Route" code="99" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.7 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Framed-IPv6-Pool" code="100" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.5.8 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Framed-IPX-Network" code="23" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.6.1-->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Framed-Appletalk-Link" code="37" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.7.1-->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Framed-Appletalk-Network" code="38" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.7.2-->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Framed-Appletalk-Zone" code="39" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.7.3-->
			<data type="OctetString"/>
		</avp>

		<avp name="ARAP-Features" code="71" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.8.1-->
			<data type="OctetString"/>
		</avp>

		<avp name="ARAP-Zone-Access" code="72" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.10.8.2 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-16 -->
				<item code="1" name="Only allow access to default zone"/>
				<item code="2" name="Use zone filter inclusively"/>
				<item code="3" name="Not used"/>
				<item code="4" name="Use zone filter exclusively"/>
			</data>
		</avp>

		<avp name="Login-IP-Host" code="14" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.1-->
			<data type="OctetString"/>
		</avp>

		<avp name="Login-IPv6-Host" code="98" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.2-->
			<data type="OctetString"/>
		</avp>

		<avp name="Login-Service" code="15" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.3 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-8 -->
				<item code="0" name="Telnet"/>
				<item code="1" name="Rlogin"/>
				<item code="2" name="TCP Clear"/>
				<item code="3" name="PortMaster (proprietary)"/>
				<item code="4" name="LAT"/>
				<item code="5" name="X25-PAD"/>
				<item code="6" name="X25-T3POS"/>
				<item code="7" name="Unassigned"/>
				<item code="8" name="TCP Clear Quiet (suppresses any NAS-generated connect string)"/>
			</data>
		</avp>

		<avp name="Login-TCP-Port" code="16" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.4.1-->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Login-LAT-Service" code="34" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.5.1-->
			<data type="OctetString"/>
		</avp>

		<avp name="Login-LAT-Node" code="35" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.5.2-->
			<data type="OctetString"/>
		</avp>

		<avp name="Login-LAT-Group" code="36" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.5.3-->
			<data type="OctetString"/>
		</avp>

		<avp name="Login-LAT-Port" code="63" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.4.11.5.4-->
			<data type="OctetString"/>
		</avp>

		<avp name="Tunneling" code="401" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.1-->
			<data type="Grouped">
				<rule avp="Tunnel-Type" required="true" max="1"/>
				<rule avp="Tunnel-Medium-Type" required="true" max="1"/>
				<rule avp="Tunnel-Client-Endpoint" required="true" max="1"/>
				<rule avp="Tunnel-Server-Endpoint" required="true" max="1"/>
				<rule avp="Tunnel-Preference" required="false" max="1"/>
				<rule avp="Tunnel-Client-Auth-Id" required="false" max="1"/>
				<rule avp="Tunnel-Server-Auth-Id" required="false" max="1"/>
				<rule avp="Tunnel-Assignment-Id" required="false" max="1"/>
				<rule avp="Tunnel-Password" required="false" max="1"/>
				<rule avp="Tunnel-Private-Group-Id" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Tunnel-Type" code="64" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.2 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-14 -->
				<item code="1" name="Point-to-Point Tunneling Protocol (PPTP)"/>
				<item code="2" name="Layer Two Forwarding (L2F)"/>
				<item code="3" name="Layer Two Tunneling Protocol (L2TP)"/>
				<item code="4" name="Ascend Tunnel Management Protocol (ATMP)"/>
				<item code="5" name="Virtual Tunneling Protocol (VTP)"/>
				<item code="6" name="IP Authentication Header in the Tunnel-mode (AH)"/>
				<item code="7" name="IP-in-IP Encapsulation (IP-IP)"/>
				<item code="8" name="Minimal IP-in-IP Encapsulation (MIN-IP-IP)"/>
				<item code="9" name="IP Encapsulating Security Payload in the Tunnel-mode (ESP)"/>
				<item code="10" name="Generic Route Encapsulation (GRE)"/>
				<item code="11" name="Bay Dial Virtual Services (DVS)"/>
				<item code="12" name="IP-in-IP Tunneling"/>
				<item code="13" name="Virtual LANs (VLAN)"/>
			</data>
		</avp>

		<avp name="Tunnel-Medium-Type" code="65" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.3 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-15 -->
				<item code="1" name="IPv4 (IP version 4)"/>
				<item code="2" name="IPv6 (IP version 6)"/>
				<item code="3" name="NSAP"/>
				<item code="4" name="HDLC (8-bit multidrop)"/>
				<item code="5" name="BBN 1822"/>
				<item code="6" name="802 (includes all 802 media plus Ethernet 'canonical format')"/>
				<item code="7" name="E.163 (POTS)"/>
				<item code="8" name="E.164 (SMDS, Frame Relay, ATM)"/>
				<item code="9" name="F.69 (Telex)"/>
				<item code="10" name="X.121 (X.25, Frame Relay)"/>
				<item code="11" name="IPX"/>
				<item code="12" name="Appletalk"/>
				<item code="13" name="Decnet IV"/>
				<item code="14" name="Banyan Vines"/>
				<item code="15" name="E.164 with NSAP format subaddress"/>
			</data>
		</avp>

		<avp name="Tunnel-Client-Endpoint" code="66" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.4 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Tunnel-Server-Endpoint" code="67" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.5 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Tunnel-Password" code="69" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.6 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Tunnel-Private-Group-Id" code="81" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.7 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Tunnel-Assignment-Id" code="82" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.8 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Tunnel-Preference" code="83" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.9 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Tunnel-Client-Auth-Id" code="90" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.10 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Tunnel-Server-Auth-Id" code="91" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.5.11 -->
			<data type="UTF8String"/>
		</avp>

		<avp name="Accounting-Input-Octets" code="363" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.1 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="Accounting-Output-Octets" code="364" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.2 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="Accounting-Input-Packets" code="365" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.3 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="Accounting-Output-Packets" code="366" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.4 -->
			<data type="Unsigned64"/>
		</avp>

		<avp name="Acct-Session-Time" code="46" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.5 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Acct-Authentic" code="45" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.6 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/radius-types/radius-types.xhtml#radius-types-11 -->
				<item code="1" name="RADIUS"/>
				<item code="2" name="Local"/>
				<item code="3" name="Remote"/>
				<item code="4" name="Diameter"/>
			</data>
		</avp>

		<avp name="Accounting-Auth-Method" code="406" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.7 -->
			<data type="Enumerated">
				<!-- http://www.iana.org/assignments/aaa-parameters/aaa-parameters.xhtml#aaa-parameters-26 -->
				<item code="1" name="PAP"/>
				<item code="2" name="CHAP"/>
				<item code="3" name="MS-CHAP-1"/>
				<item code="4" name="MS-CHAP-2"/>
				<item code="5" name="EAP"/>
				<item code="7" name="None"/>
			</data>
		</avp>

		<avp name="Acct-Delay-Time" code="41" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.8 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Acct-Link-Count" code="51" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.9 -->
			<data type="Unsigned32"/>
		</avp>

		<avp name="Acct-Tunnel-Connection" code="68" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.10 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Acct-Tunnel-Packets-Lost" code="86" must="M" may="-" must-not="V" may-encrypt="Y">
			<!-- http://tools.ietf.org/html/rfc7155#section-4.6.11 -->
			<data type="Unsigned32"/>
		</avp>
		
	</application>
</diameter>`

var tgppcxXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
  <application id="16777216" type="auth" name="TGPP CX">
    <vendor id="10415" name="TGPP"/>
    <command code="300" short="UA" name="User-Authorization">
      <request>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Destination-Host" required="false" max="1" pointer="true"/>
        <rule avp="Destination-Realm" required="true" max="1"/>
        <rule avp="User-Name" required="true" max="1"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Public-Identity" required="true" max="1"/>
        <rule avp="Visited-Network-Identifier" required="true" max="1"/>
        <rule avp="User-Authorization-Type" required="false" max="1" pointer="true"/>
        <rule avp="UAR-Flags" required="false" max="1" pointer="true"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </request>
      <answer>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Result-Code" required="false" max="1" pointer="true"/>
        <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="OC-OLR" required="false" max="1" pointer="true"/>
        <rule avp="Load" required="false"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Server-Name" required="false" max="1" pointer="true"/>
        <rule avp="Server-Capabilities" required="false" max="1" pointer="true"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Failed-AVP" required="false" max="1" pointer="true"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </answer>
    </command>
    <command code="301" short="SA" name="Server-Assignment">
      <request>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Destination-Host" required="false" max="1" pointer="true"/>
        <rule avp="Destination-Realm" required="true" max="1"/>
        <rule avp="User-Name" required="false" max="1" pointer="true"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Public-Identity" required="false"/>
        <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true"/>
        <rule avp="Server-Name" required="true" max="1"/>
        <rule avp="Server-Assignment-Type" required="true" max="1"/>
        <rule avp="User-Data-Already-Available" required="true" max="1"/>
        <rule avp="SCSCF-Restoration-Info" required="false" max="1" pointer="true"/>
        <rule avp="Multiple-Registration-Indication" required="false" max="1" pointer="true"/>
        <rule avp="Session-Priority" required="false" max="1" pointer="true"/>
        <rule avp="SAR-Flags" required="false" max="1" pointer="true"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </request>
      <answer>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Result-Code" required="false" max="1" pointer="true"/>
        <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="User-Name" required="false" max="1" pointer="true"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="OC-OLR" required="false" max="1" pointer="true"/>
        <rule avp="Load" required="false"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="User-Data" required="false"/>
        <rule avp="Charging-Information" required="false"/>
        <rule avp="Associated-Identities" required="false"/>
        <rule avp="Loose-Route-Indication" required="false"/>
        <rule avp="SAssociated-Registered-IdentitiesCSCF-Restoration-Info" required="false"/>
        <rule avp="Associated-Registered-Identities" required="false"/>
        <rule avp="Server-Name" required="false" max="1" pointer="true"/>
        <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true"/>
        <rule avp="Priviledged-Sender-Indication" required="false"/>
        <rule avp="Allowed-WAF-WWSF-Identities" required="false"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Failed-AVP" required="false" max="1" pointer="true"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </answer>
    </command>
    <command code="302" short="LI" name="Location-Info">
      <request>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Destination-Host" required="false" max="1" pointer="true"/>
        <rule avp="Destination-Realm" required="true" max="1"/>
        <rule avp="Originating-Request" required="false" max="1" pointer="true"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Public-Identity" required="true" max="1"/>
        <rule avp="User-Authorization-Type" required="false" max="1" pointer="true"/>
        <rule avp="Session-Priority" required="false" max="1" pointer="true"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </request>
      <answer>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Result-Code" required="false" max="1" pointer="true"/>
        <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="OC-OLR" required="false" max="1" pointer="true"/>
        <rule avp="Load" required="false"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Server-Name" required="false" max="1" pointer="true"/>
        <rule avp="Server-Capabilities" required="false" max="1" pointer="true"/>
        <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true"/>
        <rule avp="LIA-Flags" required="false"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Failed-AVP" required="false" max="1" pointer="true"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </answer>
    </command>
    <command code="303" short="MA" name="Multimedia-Auth">
      <request>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Destination-Realm" required="true" max="1"/>
        <rule avp="Destination-Host" required="false" max="1" pointer="true"/>
        <rule avp="User-Name" required="true" max="1"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Public-Identity" required="true" max="1"/>
        <rule avp="SIP-Auth-Data-Item" required="true" max="1"/>
        <rule avp="SIP-Number-Auth-Items" required="true" max="1"/>
        <rule avp="Server-Name" required="true" max="1"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </request>
      <answer>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Result-Code" required="false" max="1" pointer="true"/>
        <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="User-Name" required="false" max="1" pointer="true"/>
        <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
        <rule avp="OC-OLR" required="false" max="1" pointer="true"/>
        <rule avp="Load" required="false"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Public-Identity" required="false" max="1" pointer="true"/>
        <rule avp="SIP-Number-Auth-Items" required="false" max="1" pointer="true"/>
        <rule avp="SIP-Auth-Data-Item" required="false"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Failed-AVP" required="false" max="1" pointer="true"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </answer>
    </command>
    <command code="304" short="RT" name="Registration-Termination">
      <request>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Destination-Realm" required="true" max="1"/>
        <rule avp="User-Name" required="true" max="1"/>
        <rule avp="Associated-Identities" required="false"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Public-Identity" required="false"/>
        <rule avp="Deregistration-Reason" required="true" max="1"/>
        <rule avp="RTR-Flags" required="false" max="1" pointer="true"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </request>
      <answer>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Result-Code" required="false" max="1" pointer="true"/>
        <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Associated-Identities" required="false"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="Identity-with-Emergency-Registration" required="false"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Failed-AVP" required="false" max="1" pointer="true"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </answer>
    </command>
    <command code="305" short="PP" name="Push-Profile">
      <request>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Destination-Host" required="true" max="1"/>
        <rule avp="Destination-Realm" required="true" max="1"/>
        <rule avp="User-Name" required="true" max="1"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="User-Data" required="false"/>
        <rule avp="Charging-Information" required="false"/>
        <rule avp="SIP-Auth-Data-Item" required="false"/>
        <rule avp="Allowed-WAF-WWSF-Identities" required="false"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </request>
      <answer>
        <rule avp="Session-Id" required="true" max="1"/>
        <rule avp="DRMP" required="false" max="1" pointer="true"/>
        <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
        <rule avp="Result-Code" required="false" max="1" pointer="true"/>
        <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
        <rule avp="Auth-Session-State" required="true" max="1"/>
        <rule avp="Origin-Host" required="true" max="1"/>
        <rule avp="Origin-Realm" required="true" max="1"/>
        <rule avp="Supported-Features" required="false"/>
        <rule avp="AVP" required="false"/>
        <rule avp="Failed-AVP" required="false" max="1" pointer="true"/>
        <rule avp="Proxy-Info" required="false"/>
        <rule avp="Route-Record" required="false"/>
      </answer>
    </command>

  <avp name="Session-Id" code="263" must="M" may="P" must-not="V" may-encrypt="Y">
    <data type="UTF8String"  />
  </avp>
  <avp name="DRMP" code="301" must-not="V">
    <data type="Enumerated"  >
      <item code="0" name="PRIORITY_0"/>
      <item code="1" name="PRIORITY_1"/>
      <item code="2" name="PRIORITY_2"/>
      <item code="3" name="PRIORITY_3"/>
      <item code="4" name="PRIORITY_4"/>
      <item code="5" name="PRIORITY_5"/>
      <item code="6" name="PRIORITY_6"/>
      <item code="7" name="PRIORITY_7"/>
      <item code="8" name="PRIORITY_8"/>
      <item code="9" name="PRIORITY_9"/>
      <item code="10" name="PRIORITY_10"/>
      <item code="11" name="PRIORITY_11"/>
      <item code="12" name="PRIORITY_12"/>
      <item code="13" name="PRIORITY_13"/>
      <item code="14" name="PRIORITY_14"/>
      <item code="15" name="PRIORITY_15"/>
    </data>
  </avp>
  <avp name="Vendor-Specific-Application-Id" code="260" must="M" may="P" must-not="V" may-encrypt="N" >
    <data type="Grouped"  >
      <rule avp="Vendor-Id" required="false" max="1"/>
      <rule avp="Auth-Application-Id" required="false" max="1"/>
      <rule avp="Acct-Application-Id" required="false" max="1"/>
    </data>
  </avp>
  <avp name="Auth-Session-State" code="277" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Enumerated"  >
      <item code="0" name="STATE_MAINTAINED"/>
      <item code="1" name="NO_STATE_MAINTAINED"/>
    </data>
  </avp>
  <avp name="Origin-Host" code="264" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
  </avp>
  <avp name="Origin-Realm" code="296" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
  </avp>
  <avp name="Destination-Host" code="293" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
  </avp>
  <avp name="Destination-Realm" code="283" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
  </avp>
  <avp name="Supported-Features" code="628" must="V" vendor-id="10415" may-encrypt="N" >
    <data type="Grouped"  >
      <rule avp="Vendor-Id" required="true" max="1"/>
      <rule avp="Feature-List-ID" required="true" max="1"/>
      <rule avp="Feature-List" required="true" max="1"/>
    </data>
  </avp>
  <avp name="User-Name" code="1" must="M" may="P" must-not="V" may-encrypt="Y" >
    <data type="UTF8String"  />
  </avp>
  <avp name="OC-Supported-Features" code="621" must-not="V">
    <data type="Grouped"  >
      <rule avp="OC-Feature-Vector" required="false" max="1"/>
      <rule avp="AVP" required="false"/>
    </data>
  </avp>
		<avp name="OC-Feature-Vector" code="622" must-not="V">
			<data type="Unsigned64"/>
		</avp>
  <avp name="User-Identity" code="700" must="M,V" vendor-id="10415" may="-" must-not="-" may-encrypt="N" >
    <data type="Grouped"  >
      <rule avp="Public-Identity" required="false" max="1" pointer="true"/>
      <rule avp="MSISDN" required="false" max="1" pointer="true"/>
      <rule avp="External-Identifier" required="false" max="1" pointer="true"/>
    </data>
  </avp>
  <avp name="Public-Identity" code="601" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="UTF8String"  />
  </avp>
  <avp name="MSISDN" code="701" must="M,V" vendor-id="10415" may="-" must-not="-" may-encrypt="N" >
    <data type="OctetString"  />
  </avp>
  <avp name="External-Identifier" code="3111" must="M,V" vendor-id="10415" may="-" must-not="-" may-encrypt="N" >
    <data type="UTF8String"  />
  </avp>
  <avp name="Proxy-Info" code="284" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="Grouped"  >
      <rule avp="Proxy-Host" required="true" max="1"/>
      <rule avp="Proxy-State" required="true" max="1"/>
    </data>
  </avp>
  <avp name="Proxy-Host" code="280" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="DiameterIdentity"/>
  </avp>
  <avp name="Proxy-State" code="33" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="OctetString"  />
  </avp>
  <avp name="Route-Record" code="282" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="DiameterIdentity"/>
  </avp>
  <avp name="Visited-Network-Identifier" code="600" must="M,V" vendor-id="10415" may="-" must-not="-" may-encrypt="N" >
    <data type="OctetString"  />
  </avp>
  <avp name="User-Authorization-Type" code="623" must="M,V" vendor-id="10415" may="-" must-not="V" may-encrypt="N">
    <data type="Enumerated"  >
      <item code="0" name="REGISTRATION"/>
      <item code="1" name="DEREGISTRATION"/>
      <item code="2" name="CAPABILITIES"/>
    </data>
  </avp>
  <avp name="UAR-Flags" code="637" must="V" vendor-id="10415" must-not="M" may="-" may-encrypt="N">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Experimental-Result" code="297" must="M" may="P" must-not="V" may-encrypt="N">
    <data type="Grouped"  >
      <rule avp="Vendor-Id" required="true" max="1"/>
      <rule avp="Experimental-Result-Code" required="true" max="1"/>
    </data>
  </avp>
  <avp name="Experimental-Result-Code" code="298" must="M" may="P" must-not="V" may-encrypt="N">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Vendor-Id" code="266" must="M" may-encrypt="-" >
    <data type="Unsigned32"  />
  </avp>
  <avp name="OC-OLR" code="623" must-not="M,V">
    <data type="Grouped"  >
      <rule avp="OC-Sequence-Number" required="true" max="1"/>
      <rule avp="OC-Report-Type" required="true" max="1"/>
      <rule avp="OC-Reduction-Percentage" required="false" max="1"/>
      <rule avp="OC-Validity-Duration" required="false" max="1"/>
      <rule avp="AVP" required="false"/>
    </data>
  </avp>
  <avp name="OC-Sequence-Number" code="624" must-not="V">
    <data type="Unsigned64"/>
  </avp>
  <avp name="OC-Validity-Duration" code="625" must-not="V">
    <data type="Unsigned32"  />
  </avp>
  <avp name="OC-Report-Type" code="626" must-not="V">
    <data type="Enumerated"  >
      <item code="0" name="HOST_REPORT"/>
      <item code="1" name="REALM_REPORT"/>
    </data>
  </avp>
  <avp name="OC-Reduction-Percentage" code="627" must-not="V">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Load" code="650" must-not="V">
    <data type="Grouped"  >
      <rule avp="Load-Type" required="false" max="1"/>
      <rule avp="Load-Value" required="false" max="1"/>
      <rule avp="SourceID" required="false" max="1"/>
      <rule avp="AVP" required="false"/>
    </data>
  </avp>
  <avp name="Load-Value" code="652" must-not="V">
    <data type="Unsigned64"/>
  </avp>
  <avp name="Load-Type" code="651" must-not="V">
    <data type="Enumerated"  >
      <item code="0" name="HOST"/>
      <item code="1" name="PEER"/>
    </data>
  </avp>
  <avp name="Server-Name" code="602" must="M,V" vendor-id="10415" may="-" must-not="-" may-encrypt="-">
    <data type="UTF8String"  />
  </avp>
  <avp name="Server-Assignment-Type" code="614" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="Enumerated"  >
      <item code="0" name="NO_ASSIGNMENT"/>
      <item code="1" name="REGISTRATION"/>
      <item code="2" name="RE_REGISTRATION"/>
      <item code="3" name="UNREGISTERED_USER"/>
      <item code="4" name="TIMEOUT_DEREGISTRATION"/>
      <item code="5" name="USER_DEREGISTRATION"/>
      <item code="6" name="TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME"/>
      <item code="7" name="USER_DEREGISTRATION_STORE_SERVER_NAME"/>
      <item code="8" name="ADMINISTRATIVE_DEREGISTRATION"/>
      <item code="9" name="AUTHENTICATION_FAILURE"/>
      <item code="10" name="AUTHENTICATION_TIMEOUT"/>
      <item code="11" name="DEREGISTRATION_TOO_MUCH_DATA"/>
      <item code="12" name="AAA_USER_DATA_REQUEST"/>
      <item code="13" name="PGW_UPDATE"/>
      <item code="14" name="RESTORATION"/>
    </data>
  </avp>
  <avp name="User-Data-Already-Available" code="624" must="M,V" vendor-id="10415" may="-" must-not="-" may-encrypt="N">
    <data type="Enumerated"  >
      <item code="0" name="USER_DATA_NOT_AVAILABLE"/>
      <item code="1" name="USER_DATA_ALREADY_AVAILABLE"/>
    </data>
  </avp>
  <avp name="SCSCF-Restoration-Info" code="639" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="User-Name" required="true"/>
      <avp name="Restoration-Info" required="true" />
      <avp name="Registration-Time-Out" required="false"/>
      <avp name="SIP-Authentication-Scheme" required="false"/>
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="Restoration-Info" code="649" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="Path" required="true"/>
      <avp name="Contact" required="true"/>
      <avp name="Initial-CSeq-Sequence-Number" required="false"/>
      <avp name="Call-ID-SIP-Header" required="false"/>
      <avp name="Subscription-Info" required="false"/>
      <avp name="P-CSCF-Subscription-Info" required="false"/>
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="Path" code="640" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="OctetString"  />
  </avp>
  <avp name="Contact" code="641" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="OctetString"  />
  </avp>
  <avp name="Call-ID-SIP-Header" code="643" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="OctetString"  />
  </avp>
  <avp name="Subscription-Info" code="642" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="Call-ID-SIP-Header" required="true"/>
      <avp name="From-SIP-Header" required="true"/>
      <avp name="To-SIP-Header" required="true"/>
      <avp name="Record-Route" required="true"/>
      <avp name="Contact" required="true"/>
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="From-SIP-Header" code="644" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="OctetString"  />
  </avp>
  <avp name="To-SIP-Header" code="645" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="OctetString"  />
  </avp>
  <avp name="Record-Route" code="646" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="OctetString"  />
  </avp>
  <avp name="P-CSCF-Subscription-Info" code="660" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="Call-ID-SIP-Header" required="true"/>
      <avp name="From-SIP-Header" required="true"/>
      <avp name="To-SIP-Header" required="true"/>
      <avp name="Contact" required="true"/>
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="Registration-Time-Out" code="661" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Time"/>
  </avp>
  <avp name="SIP-Authentication-Scheme" code="608" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="UTF8String"  />
  </avp>
  <avp name="Multiple-Registration-Indication" code="648" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
      <item code="0" name="NOT_MULTIPLE_REGISTRATION"/>
      <item code="1" name="MULTIPLE_REGISTRATION"/>
    </data>
  </avp>
  <avp name="SAR-Flags" code="655" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Charging-Information" code="618" must="M,V" vendor-id="10415" may-encrypt="N"  >
    <data type="Grouped"  >
      <avp name="Primary-Event-Charging-Function-Name" required="false"/>
      <avp name="Secondary-Event-Charging-Function-Name" required="false"/>
      <avp name="Primary-Charging-Collection-Function-Name" required="false"/>
      <avp name="Secondary-Charging-Collection-Function-Name" required="false"/>
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="Primary-Event-Charging-Function-Name" code="619" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="DiameterURI"  />
  </avp>
  <avp name="Secondary-Event-Charging-Function-Name" code="620" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="DiameterURI"  />
  </avp>
  <avp name="Primary-Charging-Collection-Function-Name" code="621" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="DiameterURI"  />
  </avp>
  <avp name="Secondary-Charging-Collection-Function-Name" code="622" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="DiameterURI"  />
  </avp>
  <avp name="SIP-Auth-Data-Item" code="612" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="Grouped"  >
      <rule avp="SIP-Item-Number" required="false" max="1"/>
      <rule avp="SIP-Authentication-Scheme" required="false" max="1"/>
      <rule avp="SIP-Authenticate" required="false" max="1"/>
      <rule avp="SIP-Authorization" required="false" max="1"/>
      <rule avp="Confidentiality-Key" required="false" max="1"/>
      <rule avp="Integrity-Key" required="false" max="1"/>
      <rule avp="AVP" required="false"/>
    </data>
  </avp>
  <avp name="SIP-Item-Number" code="613" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="Unsigned32"  />
  </avp>
  <avp name="SIP-Authentication-Scheme" code="608" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="UTF8String"  />
  </avp>
  <avp name="SIP-Authenticate" code="609" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="OctetString"  />
  </avp>
  <avp name="SIP-Authorization" code="610" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="OctetString"  />
  </avp>
  <avp name="Confidentiality-Key" code="625" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="OctetString"  />
  </avp>
  <avp name="Integrity-Key" code="626" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="OctetString"  />
  </avp>
  <avp name="SIP-Number-Auth-Items" code="607" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="Unsigned32"  />
  </avp>
  <avp name="User-Data" code="606" must="M,V" vendor-id="10415" may-encrypt="-" >
    <data type="OctetString"  />
  </avp>
  <avp name="Associated-Identities" code="632" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="User-Name" required="false" />
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="Associated-Registered-Identities" code="647" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="User-Name" required="false" />
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="Loose-Route-Indication" code="638" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
      <item code="0" name="LOOSE_ROUTE_NOT_REQUIRED"/>
      <item code="1" name="LOOSE_ROUTE_REQUIRED"/>
    </data>
  </avp>
  <avp name="Priviledged-Sender-Indication" code="652" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
      <item code="0" name="NOT_PRIVILEDGED_SENDER"/>
      <item code="1" name="PRIVILEDGED_SENDER"/>
    </data>
  </avp>
  <avp name="Allowed-WAF-WWSF-Identities" code="656" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="WebRTC-Authentication-Function-Name" required="false" />
      <avp name="WebRTC-Web-Server-Function-Name" required="false" />
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="WebRTC-Authentication-Function-Name" code="657" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="UTF8String"  />
  </avp>
  <avp name="WebRTC-Web-Server-Function-Name" code="658" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="UTF8String"  />
  </avp>
  <avp name="Originating-Request" code="633" must="M,V" vendor-id="10415" may-encrypt="N">
    <data type="Enumerated"  >
      <item code="0" name="ORIGINATING"/>
    </data>
  </avp>
  <avp name="LIA-Flags" code="653" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Wildcarded-Public-Identity" code="634" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="UTF8String"  />
  </avp>
  <avp name="Deregistration-Reason" code="615" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="Grouped"  >
      <rule avp="Reason-Code" required="true"/>
      <rule avp="Reason-Info" required="false"/>
      <rule avp="AVP" required="false"/>
    </data>
  </avp>
  <avp name="Reason-Code" code="616" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="Enumerated"  >
      <item code="0" name="PERMANENT_TERMINATION"/>
      <item code="1" name="NEW_SERVER_ASSIGNMENT"/>
      <item code="2" name="SERVER_CHANGE"/>
      <item code="3" name="REMOVE_S_CSCF"/>
    </data>
  </avp>
  <avp name="Reason-Info" code="617" must="M,V" vendor-id="10415" may-encrypt="N" >
    <data type="UTF8String"  />
  </avp>
  <avp name="RTR-Flags" code="659" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Identity-with-Emergency-Registration" code="651" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
      <avp name="User-Name" required="true"/>
      <avp name="Public-Identity" required="true"/>
      <avp name="AVP" required="false" />
    </data>
  </avp>
  <avp name="Result-Code" code="268" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Session-Priority" code="650" must="V" vendor-id="10415" may="-" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
      <item code="0" name="PRIORITY-0" httpValue="PRIORITY-0"/>
      <item code="1" name="PRIORITY-1" httpValue="PRIORITY-1"/>
      <item code="2" name="PRIORITY-2" httpValue="PRIORITY-2"/>
      <item code="3" name="PRIORITY-3" httpValue="PRIORITY-3"/>
      <item code="4" name="PRIORITY-4" httpValue="PRIORITY-4"/>
    </data>
  </avp>
  <avp name="Server-Capabilities" code="603" must="V,M" vendor-id="10415" may="P" must-not="-" may-encrypt="N" >
    <data type="Grouped"  >
      <rule avp="Mandatory-Capability" required="false"/>
      <rule avp="Optional-Capability" required="false"/>
      <rule avp="Server-Name" required="false"/>
      <rule avp="AVP" required="false"/>
    </data>
  </avp>
  <avp name="Mandatory-Capability" code="604" must="V,M" vendor-id="10415" may="-" must-not="-" may-encrypt="N" >
    <data type="Unsigned32"  />
  </avp>
  <avp name="Optional-Capability" code="605" must="V,M" vendor-id="10415" may="P" must-not="-" may-encrypt="N" >
    <data type="Unsigned32"  />
  </avp>
  <avp name="Failed-AVP" code="279" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Grouped"/>
  </avp>
  <avp name="SourceID" code="649" must-not="V">
    <data type="DiameterIdentity"/>
  </avp>
  <avp name="Auth-Application-Id" code="258" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Feature-List-ID" code="629" must="V" vendor-id="10415" may-encrypt="N" >
    <data type="Unsigned32"  />
  </avp>
  <avp name="Feature-List" code="630" must="V" vendor-id="10415" may-encrypt="N" >
    <data type="Unsigned32"  />
  </avp>
  <avp name="Acct-Application-Id" code="259" must="M" may="P" must-not="V" may-encrypt="N">
    <data type="Unsigned32"  />
  </avp>
  <avp name="Initial-CSeq-Sequence-Number" code="654" must="V" vendor-id="10415" must-not="M" may-encrypt="N">
    <data type="Unsigned32"  />
  </avp>
  </application>
</diameter>`

var tgpprorfXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
	<application id="4" type="auth" name="TGPP">
		<vendor id="10415" name="TGPP"/>

		<avp name="TGPP-Charging-Characteristics" code="13" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="TGPP-Charging-Id" code="2" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="TGPP-GGSN-MCC-MNC" code="9" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="TGPP-IMSI" code="1" must="V" may="P" must-not="M" may-encrypt="" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="TGPP-IMSI-MCC-MNC" code="8" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="TGPP-MS-TimeZone" code="23" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="TGPP-NSAPI" code="10" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="TGPP-PDP-Type" code="3" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Ipv4"/>
				<item code="1" name="PPP"/>
				<item code="2" name="Ipv6"/>
				<item code="3" name="Ipv4v6"/>
			</data>
		</avp>

		<avp name="TGPP-RAT-Type" code="21" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="TGPP-Selection-Mode" code="12" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="TGPP-Session-Stop-Indicator" code="11" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="TGPP-SGSN-MCC-MNC" code="18" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="TGPP-User-Location-Info" code="22" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Access-Network-Charging-Identifier-Value" code="503" must="M,V"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Access-Network-Information" code="1263" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Access-Transfer-Information" code="2709" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Access-Transfer-Type" required="false" max="1"/>
				<rule avp="Access-Network-Information" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Access-Transfer-Type" code="2710" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="PS to CS Transfer"/>
				<item code="1" name="CS to PS Transfer"/>
			</data>
		</avp>

		<avp name="Account-Expiration" code="2309" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Accumulated-Cost" code="2052" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Value-Digits" required="true" max="1"/>
				<rule avp="Exponent" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Adaptations" code="1217" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Yes"/>
				<item code="1" name="No"/>
			</data>
		</avp>

		<avp name="ADC-Rule-Base-Name" code="1095" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Additional-Content-Information" code="1207" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Type-Number" required="false" max="1"/>
				<rule avp="Additional-Type-Information" required="false" max="1"/>
				<rule avp="Content-Size" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Additional-Type-Information" code="1205" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Address-Data" code="897" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Address-Domain" code="898" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Domain-Name" required="false" max="1"/>
				<rule avp="TGPP-IMSI-MCC-MNC" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Addressee-Type" code="1208" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="TO"/>
				<item code="1" name="CC"/>
				<item code="2" name="BCC"/>
			</data>
		</avp>

		<avp name="Address-Type" code="899" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="e-mail address"/>
				<item code="1" name="MSISDN"/>
				<item code="2" name="IPv4 Address"/>
				<item code="3" name="IPv6 Address"/>
				<item code="4" name="Numeric Shortcode"/>
				<item code="5" name="Alphanumeric Shortcode"/>
				<item code="6" name="Other"/>
				<item code="7" name="IMSI"/>
			</data>
		</avp>

		<avp name="AF-Charging-Identifier" code="505" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="AF-Correlation-Information" code="1276" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="AF-Charging-Identifier" required="true" max="1"/>
				<rule avp="Flows" required="false"/>
			</data>
		</avp>

		<avp name="Allocation-Retention-Priority" code="1034" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Priority-Level" required="true" max="1"/>
				<rule avp="Pre-emption-Capability" required="false" max="1"/>
				<rule avp="Pre-emption-Vulnerability" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Alternate-Charged-Party-Address" code="1280" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="AoC-Cost-Information" code="2053" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Accumulated-Cost" required="false" max="1"/>
				<rule avp="Incremental-Cost" required="false"/>
				<rule avp="Currency-Code" required="false" max="1"/>
			</data>
		</avp>

		<avp name="AoC-Format" code="2310" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="MONETARY"/>
				<item code="1" name="NON_MONETARY"/>
				<item code="2" name="CAI"/>
			</data>
		</avp>

		<avp name="AoC-Information" code="2054" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="AoC-Cost-Information" required="false" max="1"/>
				<rule avp="Tariff-Information" required="false" max="1"/>
				<rule avp="AoC-Subscription-Information" required="false" max="1"/>
			</data>
		</avp>

		<avp name="AoC-Request-Type" code="2055" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="AoC_NOT_REQUESTED"/>
				<item code="1" name="AoC_FULL"/>
				<item code="2" name="AoC_COST_ONLY"/>
				<item code="3" name="AoC_TARIFF_ONLY"/>
			</data>
		</avp>

		<avp name="AoC-Service" code="2311" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="AoC-Service-Obligatory-Type" required="false" max="1"/>
				<rule avp="AoC-Service-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="AoC-Service-Obligatory-Type" code="2312" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="NON_BINDING"/>
				<item code="1" name="BINDING"/>
			</data>
		</avp>

		<avp name="AoC-Service-Type" code="2313" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="NONE"/>
				<item code="1" name="AOC-S"/>
				<item code="2" name="AOC-D"/>
				<item code="3" name="AOC-E"/>
			</data>
		</avp>

		<avp name="AoC-Subscription-Information" code="2314" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="AoC-Service" required="false"/>
				<rule avp="AoC-Format" required="false" max="1"/>
				<rule avp="Preferred-AoC-Currency" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Application-Port-Identifer" code="3010" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Application-Provided-Called-Party-Address" code="837" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Application-Server" code="836" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Application-Server-Id" code="2101" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Application-Service-Provider-Identity" code="532" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Application-Server-Information" code="850" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Application-Server" required="false" max="1"/>
				<rule avp="Application-Provided-Called-Party-Address" required="false"/>
				<rule avp="Status- AS-Code" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Application-Session-Id" code="2103" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Applic-Id" code="1218" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Associated-Party-Address" code="2035" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Associated-URI" code="856" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Authorised-QoS" code="849" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Aux-Applic-Info" code="1219" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Base-Time-Interval" code="1265" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Basic-Service-Code" code="3411" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Bearer-Service" required="false" max="1"/>
				<rule avp="Teleservice" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Bearer-Capability" code="3412" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Bearer-Identifier" code="1020" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<!-- 3GPP TS 29.212 section 5.3.20 -->
			<data type="OctetString"/>
		</avp>

		<avp name="Bearer-Service" code="854" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="BSSID" code="2716" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Called-Asserted-Identity" code="1250" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Called-Party-Address" code="832" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Calling-Party-Address" code="831" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Carrier-Select-Routing-Information" code="2023" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Cause-Code" code="861" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Integer32"/>
		</avp>

		<avp name="CG-Address" code="846" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Change-Condition" code="2037" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Integer32"/>
		</avp>

		<avp name="Change-Time" code="2038" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Charge-Reason-Code" code="2118" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="UNKNOWN"/>
				<item code="1" name="USAGE"/>
				<item code="2" name="COMMUNICATION-ATTEMPT-CHARGE"/>
				<item code="3" name="SETUP-CHARGE"/>
				<item code="4" name="ADD-ON-CHARGE"/>
			</data>
		</avp>

		<avp name="Charged-Party" code="857" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Charging-Characteristics-Selection-Mode" code="2066" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Serving-Node-Supplied"/>
				<item code="1" name="Subscription-specific"/>
				<item code="2" name="APN-specific"/>
				<item code="3" name="Home-Default"/>
				<item code="4" name="Roaming-Default"/>
				<item code="5" name="Visiting-Default"/>
			</data>
		</avp>

		<avp name="Charging-Rule-Base-Name" code="1004" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Class-Identifier" code="1214" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Personal"/>
				<item code="1" name="Advertisement"/>
				<item code="2" name="Informational"/>
				<item code="3" name="Auto"/>
			</data>
		</avp>

		<avp name="Client-Address" code="2018" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="CN-IP-Multicast-Distribution" code="921" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="NO-IP-MULTICAST"/>
				<item code="1" name="IP-MULTICAST"/>
			</data>
		</avp>

		<avp name="CN-Operator-Selection-Entity" code="3421" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="The Serving Network has been selected by the UE"/>
				<item code="1" name="The Serving Network has been selected by the network"/>
			</data>
		</avp>

		<avp name="Content-Class" code="1220" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="text"/>
				<item code="1" name="image-basic"/>
				<item code="2" name="image-rich"/>
				<item code="3" name="video-basic"/>
				<item code="4" name="video-rich"/>
				<item code="5" name="megapixel"/>
				<item code="6" name="content-basic"/>
				<item code="7" name="content-rich"/>
			</data>
		</avp>

		<avp name="Content-Disposition" code="828" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Content-Id" code="2116" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Content-Provider-Id" code="2117" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Content-Length" code="827" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Content-Size" code="1206" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="CSG-Access-Mode" code="2317" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Closed mode"/>
				<item code="1" name="Hybrid Mode"/>
			</data>
		</avp>

		<avp name="CSG-Id" code="1437" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="CSG-Membership-Indication" code="2318" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Not CSG member"/>
				<item code="1" name="CSG Member"/>
			</data>
		</avp>

		<avp name="Content-Type" code="826" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Current-Tariff" code="2056" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Currency-Code" required="false" max="1"/>
				<rule avp="Scale-Factor" required="false" max="1"/>
				<rule avp="Rate-Element" required="false"/>
			</data>
		</avp>

		<avp name="CUG-Information" code="2304" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Data-Coding-Scheme" code="2001" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Integer32"/>
		</avp>

		<avp name="Deferred-Location-Event-Type" code="1230" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Delivery-Report-Requested" code="1216" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="No"/>
				<item code="1" name="Yes"/>
			</data>
		</avp>

		<avp name="Delivery-Status" code="2104" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Destination-Interface" code="2002" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Interface-Id" required="true" max="1"/>
				<rule avp="Interface-Text" required="true" max="1"/>
				<rule avp="Interface-Port" required="false" max="1"/>
				<rule avp="Interface-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Diagnostics" code="2039" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Integer32"/>
		</avp>

		<avp name="Domain-Name" code="1200" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="DRM-Content" code="1221" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="No"/>
				<item code="1" name="Yes"/>
			</data>
		</avp>

		<avp name="Dynamic-Address-Flag" code="2051" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Static"/>
				<item code="1" name="Dynamic"/>
			</data>
		</avp>

		<avp name="Dynamic-Address-Flag-Extension" code="2068" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Static"/>
				<item code="1" name="Dynamic"/>
			</data>
		</avp>

		<avp name="Early-Media-Description" code="1272" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SDP-TimeStamps" required="false" max="1"/>
				<rule avp="SDP-Media-Component" required="false"/>
				<rule avp="SDP-Session-Description" required="false"/>
			</data>
		</avp>

		<avp name="ePDG-Address" code="3425" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Envelope" code="1266" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Envelope-Start-Time" required="true" max="1"/>
				<rule avp="Envelope-End-Time" required="false" max="1"/>
				<rule avp="CC-Total-Octets" required="false" max="1"/>
				<rule avp="CC-Input-Octets" required="false" max="1"/>
				<rule avp="CC-Output-Octets" required="false" max="1"/>
				<rule avp="CC-Service-Specific-Units" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Envelope-End-Time" code="1267" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Envelope-Reporting" code="1268" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="DO_NOT_REPORT_ENVELOPES"/>
				<item code="1" name="REPORT_ENVELOPES"/>
				<item code="2" name="REPORT_ENVELOPES_WITH_VOLUME"/>
				<item code="3" name="REPORT_ENVELOPES_WITH_EVENTS"/>
				<item code="4" name="REPORT_ENVELOPES_WITH_VOLUME_AND_EVENTS"/>
			</data>
		</avp>

		<avp name="Envelope-Start-Time" code="1269" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Event" code="825" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Event-Charging-TimeStamp" code="1258" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Event-Type" code="823" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SIP-Method" required="false" max="1"/>
				<rule avp="Event" required="false" max="1"/>
				<rule avp="Expires" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Expires" code="888" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="File-Repair-Supported" code="1224" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="SUPPORTED"/>
				<item code="1" name="NOT_SUPPORTED"/>
			</data>
		</avp>

		<avp name="Fixed-User-Location-Info" code="2825" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SSID" required="false" max="1"/>
				<rule avp="BSSID" required="false" max="1"/>
				<rule avp="Logical-Access-Id" required="true" max="1"/>
				<rule avp="Physical-Access-Id" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Flows" code="510" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Media-Component-Number" required="true" max="1"/>
				<rule avp="Flow-Number" required="false"/>
			</data>
		</avp>

		<avp name="From-Address" code="2708" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Forwarding-Pending" code="3415" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Forwarding not pending"/>
				<item code="1" name="Forwarding pending"/>
			</data>
		</avp>

		<avp name="GGSN-Address" code="847" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Guaranteed-Bitrate-DL" code="1025" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Guaranteed-Bitrate-UL" code="1026" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Extended-GBR-DL" code="2850" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Extended-GBR-UL" code="2851" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="IMS-Application-Reference-Identifier" code="2601" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="IMS-Charging-Identifier" code="841" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="IMS-Communication-Service-Identifier" code="1281" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="IMS-Emergency-Indicator" code="2322" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Non Emergency"/>
				<item code="1" name="Emergency"/>
			</data>
		</avp>

		<avp name="IMS-Information" code="876" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Event-Type" required="false" max="1"/>
				<rule avp="Role-Of-Node" required="false" max="1"/>
				<rule avp="Node-Functionality" required="true" max="1"/>
				<rule avp="User-Session-Id" required="false" max="1"/>
				<rule avp="Outgoing-Session-Id" required="false" max="1"/>
				<rule avp="Session-Priority" required="false" max="1"/>
				<rule avp="Calling-Party-Address" required="false"/>
				<rule avp="Called-Party-Address" required="false" max="1"/>
				<rule avp="Called-Asserted-Identity" required="false"/>
				<rule avp="Number-Portability-Routing-Information" required="false" max="1"/>
				<rule avp="Carrier-Select-Routing-Information" required="false" max="1"/>
				<rule avp="Alternate-Charged-Party-Address" required="false" max="1"/>
				<rule avp="Requested-Party-Address" required="false"/>
				<rule avp="Associated-URI" required="false"/>
				<rule avp="Time-Stamps" required="false" max="1"/>
				<rule avp="Application-Server-Information" required="false"/>
				<rule avp="Inter-Operator-Identifier" required="false"/>
				<rule avp="Transit-IOI-List" required="false"/>
				<rule avp="IMS-Charging-Identifier" required="false" max="1"/>
				<rule avp="SDP-Session-Description" required="false"/>
				<rule avp="SDP-Media-Component" required="false"/>
				<rule avp="Served-Party-IP-Address" required="false" max="1"/>
				<rule avp="Server-Capabilities" required="false" max="1"/>
				<rule avp="Trunk-Group-Id" required="false" max="1"/>
				<rule avp="Bearer-Service" required="false" max="1"/>
				<rule avp="Service-Id" required="false" max="1"/>
				<rule avp="Service-Specific-Info" required="false"/>
				<rule avp="Message-Body" required="false"/>
				<rule avp="Cause-Code" required="false" max="1"/>
				<rule avp="Reason-Header" required="false"/>
				<rule avp="Access-Network-Information" required="false"/>
				<rule avp="Early-Media-Description" required="false"/>
				<rule avp="IMS-Communication-Service-Identifier" required="false" max="1"/>
				<rule avp="IMS-Application-Reference-Identifier" required="false" max="1"/>
				<rule avp="Online-Charging-Flag" required="false" max="1"/>
				<rule avp="Real-Time-Tariff-Information" required="false" max="1"/>
				<rule avp="Account-Expiration" required="false" max="1"/>
				<rule avp="Initial-IMS-Charging-Identifier" required="false" max="1"/>
				<rule avp="NNI-Information" required="false"/>
				<rule avp="From-Address" required="false" max="1"/>
				<rule avp="IMS-Emergency-Indicator" required="false" max="1"/>
				<rule avp="IMS-Visited-Network-Identifier" required="false" max="1"/>
				<rule avp="Access-Transfer-Information" required="false"/>
				<rule avp="Related-IMS-Charging-Identifier" required="false" max="1"/>
				<rule avp="Related-IMS-Charging-Identifier-Node" required="false" max="1"/>
				<rule avp="Route-Header-Received" required="false" max="1"/>
				<rule avp="Route-Header-Transmitted" required="false" max="1"/>
				<rule avp="Instance-Id" required="false" max="1"/>
				<rule avp="TAD-Identifier" required="false" max="1"/>
			</data>
		</avp>

		<avp name="IMS-Visited-Network-Identifier" code="2713" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="IMSI-Unauthenticated-Flag" code="2308" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Authenticated"/>
				<item code="1" name="Unauthenticated"/>
			</data>
		</avp>

		<avp name="Incoming-Trunk-Group-Id" code="852" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Incremental-Cost" code="2062" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Value-Digits" required="true" max="1"/>
				<rule avp="Exponent" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Initial-IMS-Charging-Identifier" code="2321" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Instance-Id" code="3402" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Interface-Id" code="2003" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Interface-Port" code="2004" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Interface-Text" code="2005" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Interface-Type" code="2006" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Unknown"/>
				<item code="1" name="MOBILE_ORIGINATING"/>
				<item code="2" name="MOBILE_TERMINATING"/>
				<item code="3" name="APPLICATION_ORIGINATING"/>
				<item code="4" name="APPLICATION_TERMINATION"/>
			</data>
		</avp>

		<avp name="Inter-Operator-Identifier" code="838" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Originating-IOI" required="false" max="1"/>
				<rule avp="Terminating-IOI" required="false" max="1"/>
			</data>
		</avp>

		<avp name="IP-Realm-Default-Indication" code="2603" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Default IP Realm Not used"/>
				<item code="1" name="Default IP realm used"/>
			</data>
		</avp>

		<avp name="ISUP-Cause" code="3416" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="ISUP-Cause-Location" required="false" max="1"/>
				<rule avp="ISUP-Cause-Value" required="false" max="1"/>
				<rule avp="ISUP-Cause-Diagnostic" required="false" max="1"/>
			</data>
		</avp>

		<avp name="ISUP-Cause-Diagnostics" code="3422" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="ISUP-Cause-Location" code="3423" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="ISUP-Cause-Value" code="3424" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="ISUP-Location-Number" code="3414" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="LCS-APN" code="1231" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="LCS-Client-Dialed-By-MS" code="1233" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="LCS-Client-External-Id" code="1234" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="LCS-Client-Id" code="1232" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="LCS-Client-Type" required="false" max="1"/>
				<rule avp="LCS-Client-External-Id" required="false" max="1"/>
				<rule avp="LCS-Client-Dialed-By-MS" required="false" max="1"/>
				<rule avp="LCS-Client-Name" required="false" max="1"/>
				<rule avp="LCS-APN" required="false" max="1"/>
				<rule avp="LCS-Requestor-Id" required="false" max="1"/>
			</data>
		</avp>

		<avp name="LCS-Client-Name" code="1235" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="LCS-Data-Coding-Scheme" required="false" max="1"/>
				<rule avp="LCS-Name-String" required="false" max="1"/>
				<rule avp="LCS-Format-Indicator" required="false" max="1"/>
			</data>
		</avp>

		<avp name="LCS-Client-Type" code="1241" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="EMERGENCY_SERVICES"/>
				<item code="1" name="VALUE_ADDED_SERVICES"/>
				<item code="2" name="PLMN_OPERATOR_SERVICES"/>
				<item code="3" name="LAWFUL_INTERCEPT_SERVICES"/>
			</data>
		</avp>

		<avp name="LCS-Data-Coding-Scheme" code="1236" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="LCS-Format-Indicator" code="1237" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="LOGICAL_NAME"/>
				<item code="1" name="EMAIL_ADDRESS"/>
				<item code="2" name="MSISDN"/>
				<item code="3" name="URL"/>
				<item code="4" name="SIP_URL"/>
			</data>
		</avp>

		<avp name="LCS-Information" code="878" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="LCS-Client-Id" required="false" max="1"/>
				<rule avp="Location-Type" required="false" max="1"/>
				<rule avp="Location-Estimate" required="false" max="1"/>
				<rule avp="Positioning-Data" required="false" max="1"/>
				<rule avp="TGPP-IMSI" required="false" max="1"/>
				<rule avp="MSISDN" required="false" max="1"/>
			</data>
		</avp>

		<avp name="LCS-Name-String" code="1238" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="LCS-Requestor-Id" code="1239" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="LCS-Data-Coding-Scheme" required="false" max="1"/>
				<rule avp="LCS-Requestor-Id-String" required="false" max="1"/>
			</data>
		</avp>

		<avp name="LCS-Requestor-Id-String" code="1240" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Local-GW-Inserted-Indication" code="2604" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Local GW Not Inserted"/>
				<item code="1" name="Local GW Inserted"/>
			</data>
		</avp>

		<avp name="Local-Sequence-Number" code="2063" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Location-Estimate" code="1242" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Location-Estimate-Type" code="1243" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="CURRENT_LOCATION"/>
				<item code="1" name="CURRENT_LAST_KNOWN_LOCATION"/>
				<item code="2" name="INITIAL_LOCATION"/>
				<item code="3" name="ACTIVATE_DEFERRED_LOCATION"/>
				<item code="4" name="CANCEL_DEFERRED_LOCATION"/>
			</data>
		</avp>

		<avp name="Location-Type" code="1244" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Location-Estimate-Type" required="false" max="1"/>
				<rule avp="Deferred-Location-Event-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Low-Balance-Indication" code="2020" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="NOT-APPLICABLE"/>
				<item code="1" name="YES"/>
			</data>
		</avp>

		<avp name="Low-Priority-Indicator" code="2602" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="NO"/>
				<item code="1" name="YES"/>
			</data>
		</avp>

		<avp name="Mandatory-Capability" code="604" must="V,M"	may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Max-Requested-Bandwidth-DL" code="515" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Max-Requested-Bandwidth-UL" code="516" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Extended-Max-Requested-BW-DL" code="554" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Extended-Max-Requested-BW-UL" code="555" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="MBMS-2G-3G-Indicator" code="907" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="2G"/>
				<item code="1" name="3G"/>
				<item code="2" name="2G-AND-3G"/>
			</data>
		</avp>

		<avp name="MBMS-Charged-Party" code="2323" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Content Provider"/>
				<item code="1" name="Subscriber"/>
			</data>
		</avp>

		<avp name="MBMS-GW-Address" code="2307" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="MBMS-Information" code="880" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="TMGI" required="false" max="1"/>
				<rule avp="MBMS-Service-Type" required="false" max="1"/>
				<rule avp="MBMS-User-Service-Type" required="false" max="1"/>
				<rule avp="File-Repair-Supported" required="false" max="1"/>
				<rule avp="Required-MBMS-Bearer-Capabilities" required="false" max="1"/>
				<rule avp="MBMS-2G-3G-Indicator" required="false" max="1"/>
				<rule avp="RAI" required="false" max="1"/>
				<rule avp="MBMS-Service-Area" required="false"/>
				<rule avp="MBMS-Session-Identity" required="false" max="1"/>
				<rule avp="CN-IP-Multicast-Distribution" required="false" max="1"/>
				<rule avp="MBMS-GW-Address" required="false" max="1"/>
				<rule avp="MBMS-Charged-Party" required="false" max="1"/>
				<rule avp="MSISDN" required="false"/>
			</data>
		</avp>

		<avp name="MBMS-Service-Area" code="903" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="MBMS-Service-Type" code="906" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="MULTICAST"/>
				<item code="1" name="BROADCAST"/>
			</data>
		</avp>

		<avp name="MBMS-Session-Identity" code="908" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="MBMS-User-Service-Type" code="1225" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="1" name="DOWNLOAD"/>
				<item code="2" name="STREAMING"/>
			</data>
		</avp>

		<avp name="Media-Initiator-Flag" code="882" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="called party"/>
				<item code="1" name="calling party"/>
				<item code="2" name="unknown"/>
			</data>
		</avp>

		<avp name="Media-Initiator-Party" code="1288" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Message-Body" code="889" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Content-Type" required="true" max="1"/>
				<rule avp="Content-Length" required="true" max="1"/>
				<rule avp="Content-Disposition" required="false" max="1"/>
				<rule avp="Originator" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Message-Class" code="1213" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Class-Identifier" required="false" max="1"/>
				<rule avp="Token-Text" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Message-Id" code="1210" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Message-Size" code="1212" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Message-Type" code="1211" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="1" name="m-send-req"/>
				<item code="2" name="m-send-conf"/>
				<item code="3" name="m-notification-ind"/>
				<item code="4" name="m-notifyresp-ind"/>
				<item code="5" name="m-retrieve-conf"/>
				<item code="6" name="m-acknowledge-ind"/>
				<item code="7" name="m-delivery-ind"/>
				<item code="8" name="m-read-rec-ind"/>
				<item code="9" name="m-read-orig-ind"/>
				<item code="10" name="m-forward-req"/>
				<item code="11" name="m-forward-conf"/>
				<item code="12" name="m-mbox-store-conf"/>
				<item code="13" name="m-mbox-view-conf"/>
				<item code="14" name="m-mbox-upload-conf"/>
				<item code="15" name="m-mbox-delete-conf"/>
			</data>
		</avp>

		<avp name="MMBox-Storage-Requested" code="1248" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="No"/>
				<item code="1" name="Yes"/>
			</data>
		</avp>

		<avp name="MM-Content-Type" code="1203" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Type-Number" required="false" max="1"/>
				<rule avp="Additional-Type-Information" required="false" max="1"/>
				<rule avp="Content-Size" required="false" max="1"/>
				<rule avp="Additional-Content-Information" required="false"/>
			</data>
		</avp>

		<avp name="MME-Name" code="2402" must="V,M"	may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="MME-Number-for-MT-SMS" code="1645" must="V"	may="-" must-not="M" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="MME-Realm" code="2408" must="V"	may="-" must-not="M" may-encrypt="N" vendor-id="10415">
			<data type="DiameterIdentity"/>
		</avp>

		<avp name="MMS-Information" code="877" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Originator-Address" required="false" max="1"/>
				<rule avp="Recipient-Address" required="false"/>
				<rule avp="Submission-Time" required="false" max="1"/>
				<rule avp="MM-Content-Type" required="false" max="1"/>
				<rule avp="Priority" required="false" max="1"/>
				<rule avp="Message-Id" required="false" max="1"/>
				<rule avp="Message-Type" required="false" max="1"/>
				<rule avp="Message-Size" required="false" max="1"/>
				<rule avp="Message-Class" required="false" max="1"/>
				<rule avp="Delivery-Report-Requested" required="false" max="1"/>
				<rule avp="Read-Reply-Report-Requested" required="false" max="1"/>
				<rule avp="MMBox-Storage-Requested" required="false" max="1"/>
				<rule avp="Applic-Id" required="false" max="1"/>
				<rule avp="Reply-Applic-Id" required="false" max="1"/>
				<rule avp="Aux-Applic-Info" required="false" max="1"/>
				<rule avp="Content-Class" required="false" max="1"/>
				<rule avp="DRM-Content" required="false" max="1"/>
				<rule avp="Adaptations" required="false" max="1"/>
				<rule avp="VASP-Id" required="false" max="1"/>
				<rule avp="VAS-Id" required="false" max="1"/>
			</data>
		</avp>

		<avp name="MMTel-Information" code="2030" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Supplementary-Service" required="false"/>
			</data>
		</avp>

		<avp name="MMTel-SService-Type" code="2031" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="MSC-Address" code="3417" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="MSISDN" code="701" must="V,M"	may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="MTC-IWF-Address" code="3406" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Neighbour-Node-Address" code="2705" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Network-Call-Reference-Number" code="3418" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Next-Tariff" code="2057" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Currency-Code" required="false" max="1"/>
				<rule avp="Scale-Factor" required="false" max="1"/>
				<rule avp="Rate-Element" required="false"/>
			</data>
		</avp>

		<avp name="NNI-Information" code="2703" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Session-Direction" required="false" max="1"/>
				<rule avp="NNI-Type" required="false" max="1"/>
				<rule avp="Relationship-Mode" required="false" max="1"/>
				<rule avp="Neighbour-Node-Address" required="false" max="1"/>
			</data>
		</avp>

		<avp name="NNI-Type" code="2704" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="non-roaming"/>
				<item code="1" name="roaming without loopback"/>
				<item code="2" name="roaming with loopback"/>
			</data>
		</avp>

		<avp name="Node-Functionality" code="862" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="S-CSCF"/>
				<item code="1" name="P-CSCF"/>
				<item code="2" name="I-CSCF"/>
				<item code="3" name="MRFC"/>
				<item code="4" name="MGCF"/>
				<item code="5" name="BGCF"/>
				<item code="6" name="AS"/>
				<item code="7" name="IBCF"/>
				<item code="8" name="S-GW"/>
				<item code="9" name="P-GW"/>
				<item code="10" name="HSGW"/>
				<item code="11" name="E-CSCF"/>
				<item code="12" name="MME"/>
				<item code="13" name="TRF"/>
				<item code="14" name="TF"/>
				<item code="15" name="ATCF"/>
				<item code="16" name="Proxy Function"/>
				<item code="17" name="ePDG"/>
			</data>
		</avp>

		<avp name="Node-Id" code="2064" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Number-Of-Diversions" code="2034" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Number-Of-Messages-Sent" code="2019" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Number-Of-Messages-Successfully-Exploded" code="2111" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Number-Of-Messages-Successfully-Sent" code="2112" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Number-Of-Participants" code="885" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Number-Of-Received-Talk-Bursts" code="1282" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Number-Of-Talk-Bursts" code="1283" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Number-Portability-Routing-Information" code="2024" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Offline-Charging" code="1278" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Quota-Consumption-Time" required="false" max="1"/>
				<rule avp="Time-Quota-Mechanism" required="false" max="1"/>
				<rule avp="Envelope-Reporting" required="false" max="1"/>
				<rule avp="Multiple-Services-Credit-Control" required="false"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="Online-Charging-Flag" code="2303" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="ECF address not provided"/>
				<item code="1" name="ECF address provided"/>
			</data>
		</avp>

		<avp name="Optional-Capability" code="605" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Originating-IOI" code="839" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Originator-SCCP-Address" code="2008" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Originator" code="864" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Calling Party"/>
				<item code="1" name="Called Party"/>
			</data>
		</avp>

		<avp name="Originator-Address" code="886" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Address-Type" required="false" max="1"/>
				<rule avp="Address-Data" required="false" max="1"/>
				<rule avp="Address-Domain" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Originator-Received-Address" code="2027" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Address-Type" required="false" max="1"/>
				<rule avp="Address-Data" required="false" max="1"/>
				<rule avp="Address-Domain" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Originator-Interface" code="2009" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Interface-Id" required="true" max="1"/>
				<rule avp="Interface-Text" required="true" max="1"/>
				<rule avp="Interface-Port" required="false" max="1"/>
				<rule avp="Interface-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Outgoing-Session-Id" code="2320" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Outgoing-Trunk-Group-Id" code="853" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Participant-Access-Priority" code="1259" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="1" name="Pre-emptive priority"/>
				<item code="2" name="High priority"/>
				<item code="3" name="Normal priority"/>
				<item code="4" name="Low priority"/>
			</data>
		</avp>

		<avp name="Participant-Action-Type" code="2049" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="CREATE_CONF"/>
				<item code="1" name="JOIN_CONF"/>
				<item code="2" name="INVITE_INTO_CONF"/>
				<item code="3" name="QUIT_CONF"/>
			</data>
		</avp>

		<avp name="Participant-Group" code="1260" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Called-Party-Address" required="false" max="1"/>
				<rule avp="Participant-Access-Priority" required="false" max="1"/>
				<rule avp="User-Participating-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Participants-Involved" code="887" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="PDN-Connection-Charging-Id" code="2050" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="PDP-Address" code="1227" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="PDP-Context-Type" code="1247" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Primary"/>
				<item code="1" name="Secondary"/>
			</data>
		</avp>

		<avp name="PDP-Address-Prefix-Length" code="2606" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="PoC-Change-Condition" code="1261" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="ServiceChange"/>
				<item code="1" name="VolumeLimit"/>
				<item code="2" name="TimeLimit"/>
				<item code="3" name="NumberofTalkBurstLimit"/>
				<item code="4" name="NumberofActiveParticipants"/>
				<item code="5" name="TariffTime"/>
			</data>
		</avp>

		<avp name="PoC-Change-Time" code="1262" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="PoC-Controlling-Address" code="858" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="PoC-Event-Type" code="2025" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Normal"/>
				<item code="1" name="Instant Ppersonal Aalert event"/>
				<item code="2" name="PoC Group Advertisement event"/>
				<item code="3" name="Early Ssession Setting-up event"/>
				<item code="4" name="PoC Talk Burst"/>
			</data>
		</avp>

		<avp name="PoC-Group-Name" code="859" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="PoC-Information" code="879" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="PoC-Server-Role" required="false" max="1"/>
				<rule avp="PoC-Session-Type" required="false" max="1"/>
				<rule avp="PoC-User-Role" required="false" max="1"/>
				<rule avp="PoC-Session-Initiation-type" required="false" max="1"/>
				<rule avp="PoC-Event-Type" required="false" max="1"/>
				<rule avp="Number-Of-Participants" required="false" max="1"/>
				<rule avp="Participants-Involved" required="false"/>
				<rule avp="Participant-Group" required="false"/>
				<rule avp="Talk-Burst-Exchange" required="false"/>
				<rule avp="PoC-Controlling-Address" required="false" max="1"/>
				<rule avp="PoC-Group-Name" required="false" max="1"/>
				<rule avp="PoC-Session-Id" required="false" max="1"/>
				<rule avp="Charged-Party" required="false" max="1"/>
			</data>
		</avp>

		<avp name="PoC-Server-Role" code="883" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Participating PoC Server"/>
				<item code="1" name="Controlling PoC Server"/>
			</data>
		</avp>

		<avp name="PoC-Session-Id" code="1229" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="PoC-Session-Initiation-type" code="1277" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Pre-established"/>
				<item code="1" name="On-demand"/>
			</data>
		</avp>

		<avp name="PoC-Session-Type" code="884" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="1 to 1 PoC session"/>
				<item code="1" name="Chat PoC group session"/>
				<item code="2" name="Pre-arranged PoC group session"/>
				<item code="3" name="Ad-hoc PoC group session"/>
			</data>
		</avp>

		<avp name="PoC-User-Role" code="1252" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="PoC-User-Role-Ids" required="false" max="1"/>
				<rule avp="PoC-User-Role-info-Units" required="false" max="1"/>
			</data>
		</avp>

		<avp name="PoC-User-Role-Ids" code="1253" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="PoC-User-Role-info-Units" code="1254" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="1" name="Moderator"/>
				<item code="2" name="Dispatcher"/>
				<item code="3" name="Session-Owner"/>
				<item code="4" name="Session-Participant"/>
			</data>
		</avp>

		<avp name="Positioning-Data" code="1245" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Preferred-AoC-Currency" code="2315" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Presence-Reporting-Area-Identifier" code="2821" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Presence-Reporting-Area-Information" code="2822" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Presence-Reporting-Area-Identifier" required="false" max="1"/>
				<rule avp="Presence-Reporting-Area-Status" required="false" max="1"/>
				<rule avp="Presence-Reporting-Area-Elements-List" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="Presence-Reporting-Area-Status" code="2823" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Priority" code="1209" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Low"/>
				<item code="1" name="Normal"/>
				<item code="2" name="High"/>
			</data>
		</avp>

		<avp name="Priority-Indication" code="3006" must="V,M"	may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Non-Priority"/>
				<item code="1" name="Priority"/>
			</data>
		</avp>

		<avp name="Priority-Level" code="1046" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Pre-emption-Capability" code="1047" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="PRE-EMPTION_CAPABILITY_ENABLED"/>
				<item code="1" name="PRE-EMPTION_CAPABILITY_DISABLED"/>
			</data>
		</avp>

		<avp name="Pre-emption-Vulnerability" code="1048" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="PRE-EMPTION_VULNERABILITY_ENABLED"/>
				<item code="1" name="PRE-EMPTION_VULNERABILITY_DISABLED"/>
			</data>
		</avp>

		<avp name="PS-Append-Free-Format-Data" code="867" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Append"/>
				<item code="1" name="Overwrite"/>
			</data>
		</avp>

		<avp name="PS-Free-Format-Data" code="866" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="PS-Furnish-Charging-Information" code="865" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="TGPP-Charging-Id" required="true" max="1"/>
				<rule avp="PS-Free-Format-Data" required="true" max="1"/>
				<rule avp="PS-Append-Free-Format-Data" required="false" max="1"/>
			</data>
		</avp>

		<avp name="PS-Information" code="874" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="TGPP-Charging-Id" required="false" max="1"/>
				<rule avp="PDN-Connection-Charging-Id" required="false" max="1"/>
				<rule avp="Node-Id" required="false" max="1"/>
				<rule avp="TGPP-PDP-Type" required="false" max="1"/>
				<rule avp="PDP-Address" required="false"/>
				<rule avp="PDP-Address-Prefix-Length" required="false" max="1"/>
				<rule avp="Dynamic-Address-Flag" required="false" max="1"/>
				<rule avp="Dynamic-Address-Flag-Extension" required="false" max="1"/>
				<rule avp="QoS-Information" required="false" max="1"/>
				<rule avp="SGSN-Address" required="false"/>
				<rule avp="GGSN-Address" required="false"/>
				<rule avp="TDF-IP-Address" required="false"/>
				<rule avp="SGW-Address" required="false"/>
				<rule avp="ePDG-Address" required="false"/>
				<rule avp="CG-Address" required="false" max="1"/>
				<rule avp="Serving-Node-Type" required="false" max="1"/>
				<rule avp="SGW-Change" required="false" max="1"/>
				<rule avp="TGPP-IMSI-MCC-MNC" required="false" max="1"/>
				<rule avp="IMSI-Unauthenticated-Flag" required="false" max="1"/>
				<rule avp="TGPP-GGSN-MCC-MNC" required="false" max="1"/>
				<rule avp="TGPP-NSAPI" required="false" max="1"/>
				<rule avp="Called-Station-Id" required="false" max="1"/>
				<rule avp="TGPP-Session-Stop-Indicator" required="false" max="1"/>
				<rule avp="TGPP-Selection-Mode" required="false" max="1"/>
				<rule avp="TGPP-Charging-Characteristics" required="false" max="1"/>
				<rule avp="Charging-Characteristics-Selection-Mode" required="false" max="1"/>
				<rule avp="TGPP-SGSN-MCC-MNC" required="false" max="1"/>
				<rule avp="TGPP-MS-TimeZone" required="false" max="1"/>
				<rule avp="Charging-Rule-Base-Name" required="false" max="1"/>
				<rule avp="ADC-Rule-Base-Name" required="false" max="1"/>
				<rule avp="TGPP-User-Location-Info" required="false" max="1"/>
				<rule avp="User-Location-Info-Time" required="false" max="1"/>
				<rule avp="User-CSG-Information" required="false" max="1"/>
				<rule avp="Presence-Reporting-Area-Information" required="false" max="1"/>
				<rule avp="TGPP2-BSID" required="false" max="1"/>
				<rule avp="TWAN-User-Location-Info" required="false" max="1"/>
				<rule avp="TGPP-RAT-Type" required="false" max="1"/>
				<rule avp="PS-Furnish-Charging-Information" required="false" max="1"/>
				<rule avp="PDP-Context-Type" required="false" max="1"/>
				<rule avp="Offline-Charging" required="false" max="1"/>
				<rule avp="Traffic-Data-Volumes" required="false"/>
				<rule avp="Service-Data-Container" required="false"/>
				<rule avp="User-Equipment-Info" required="false" max="1"/>
				<rule avp="Terminal-Information" required="false" max="1"/>
				<rule avp="Start-Time" required="false" max="1"/>
				<rule avp="Stop-Time" required="false" max="1"/>
				<rule avp="Change-Condition" required="false" max="1"/>
				<rule avp="Diagnostics" required="false" max="1"/>
				<rule avp="Low-Priority-Indicator" required="false" max="1"/>
				<rule avp="MME-Number-for-MT-SMS" required="false" max="1"/>
				<rule avp="MME-Name" required="false" max="1"/>
				<rule avp="MME-Realm" required="false" max="1"/>
				<rule avp="Logical-Access-Id" required="false" max="1"/>
				<rule avp="Physical-Access-Id" required="false" max="1"/>
				<rule avp="Fixed-User-Location-Info" required="false" max="1"/>
				<rule avp="CN-Operator-Selection-Entity" required="false" max="1"/>
			</data>
		</avp>

		<avp name="QoS-Information" code="1016" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Grouped">
				<rule avp="QoS-Class-Identifier" required="false" max="1"/>
				<rule avp="Max-Requested-Bandwidth-UL" required="false" max="1"/>
				<rule avp="Max-Requested-Bandwidth-DL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-UL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-DL" required="false" max="1"/>
				<rule avp="Guaranteed-Bitrate-UL" required="false" max="1"/>
				<rule avp="Guaranteed-Bitrate-DL" required="false" max="1"/>
				<rule avp="Extended-GBR-UL" required="false" max="1"/>
				<rule avp="Extended-GBR-DL" required="false" max="1"/>
				<rule avp="Bearer-Identifier" required="false" max="1"/>
				<rule avp="Allocation-Retention-Priority" required="false" max="1"/>
				<rule avp="APN-Aggregate-Max-Bitrate-UL" required="false" max="1"/>
				<rule avp="APN-Aggregate-Max-Bitrate-DL" required="false" max="1"/>
				<rule avp="Extended-APN-AMBR-UL" required="false" max="1"/>
				<rule avp="Extended-APN-AMBR-DL" required="false" max="1"/>
				<rule avp="Conditional-APN-Aggregate-Max-Bitrate" required="false"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="QoS-Class-Identifier" code="1028" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="1" name="QCI_1"/>
				<item code="2" name="QCI_2"/>
				<item code="3" name="QCI_3"/>
				<item code="4" name="QCI_4"/>
				<item code="5" name="QCI_5"/>
				<item code="6" name="QCI_6"/>
				<item code="7" name="QCI_7"/>
				<item code="8" name="QCI_8"/>
				<item code="9" name="QCI_9"/>
				<item code="65" name="QCI_65"/>
				<item code="66" name="QCI_66"/>
				<item code="69" name="QCI_69"/>
				<item code="70" name="QCI_70"/>
				<item code="75" name="QCI_75"/>
				<item code="79" name="QCI_79"/>
			</data>
		</avp>

		<avp name="Quota-Consumption-Time" code="881" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Quota-Holding-Time" code="871" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="RAI" code="909" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Rate-Element" code="2058" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="CC-Unit-Type" required="true" max="1"/>
				<rule avp="Charge-Reason-Code" required="false" max="1"/>
				<rule avp="Unit-Value" required="false" max="1"/>
				<rule avp="Unit-Cost" required="false" max="1"/>
				<rule avp="Unit-Quota-Threshold" required="false" max="1"/>
			</data>
		</avp>

		<avp name="RAT-Type" code="1032" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="WLAN"/>
				<item code="1" name="VIRTUAL"/>
				<item code="1000" name="UTRAN"/>
				<item code="1001" name="GERAN"/>
				<item code="1002" name="GAN"/>
				<item code="1003" name="HSPA_EVOLUTION"/>
				<item code="1004" name="EUTRAN"/>
				<item code="2000" name="CDMA2000_1X"/>
				<item code="2001" name="HRPD"/>
				<item code="2002" name="UMB"/>
				<item code="2003" name="EHRPD"/>
			</data>
		</avp>

		<avp name="Read-Reply-Report-Requested" code="1222" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="No"/>
				<item code="1" name="Yes"/>
			</data>
		</avp>

		<avp name="Real-Time-Tariff-Information" code="2305" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Tariff-Information" required="false" max="1"/>
				<rule avp="Tariff-XML" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Reason-Header" code="3401" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Received-Talk-Burst-Time" code="1284" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Received-Talk-Burst-Volume" code="1285" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Recipient-Address" code="1201" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Address-Type" required="false" max="1"/>
				<rule avp="Address-Data" required="false" max="1"/>
				<rule avp="Address-Domain" required="false" max="1"/>
				<rule avp="Addressee-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Recipient-Info" code="2026" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Destination-Interface" required="false" max="1"/>
				<rule avp="Recipient-Address" required="false"/>
				<rule avp="Recipient-Received-Address" required="false"/>
				<rule avp="Recipient-SCCP-Address" required="false" max="1"/>
				<rule avp="SM-Protocol-Id" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Recipient-Received-Address" code="2028" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Address-Type" required="false" max="1"/>
				<rule avp="Address-Data" required="false" max="1"/>
				<rule avp="Address-Domain" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Recipient-SCCP-Address" code="2010" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Reference-Number" code="3007" must="V,M"	may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Refund-Information" code="2022" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Relationship-Mode" code="2706" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="trusted"/>
				<item code="1" name="non-trusted"/>
			</data>
		</avp>

		<avp name="Related-IMS-Charging-Identifier" code="2711" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Related-IMS-Charging-Identifier-Node" code="2712" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Remaining-Balance" code="2021" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Unit-Value" required="true" max="1"/>
				<rule avp="Currency-Code" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Reply-Applic-Id" code="1223" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Reply-Path-Requested" code="2011" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="No Reply Path Set"/>
				<item code="1" name="Reply path Set"/>
			</data>
		</avp>

		<avp name="Reporting-Reason" code="872" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="THRESHOLD"/>
				<item code="1" name="QHT"/>
				<item code="2" name="FINAL"/>
				<item code="3" name="QUOTA_EXHAUSTED"/>
				<item code="4" name="VALIDITY_TIME"/>
				<item code="5" name="OTHER_QUOTA_TYPE"/>
				<item code="6" name="RATING_CONDITION_CHANGE"/>
				<item code="7" name="FORCED_REAUTHORISATION"/>
				<item code="8" name="POOL_EXHAUSTED"/>
			</data>
		</avp>

		<avp name="Requested-Party-Address" code="1251" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Required-MBMS-Bearer-Capabilities" code="901" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Role-Of-Node" code="829" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="ORIGINATING_ROLE"/>
				<item code="1" name="TERMINATING_ROLE"/>
				<item code="2" name="FORWARDING_ROLE"/>
			</data>
		</avp>

		<avp name="Route-Header-Received" code="3403" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Route-Header-Transmitted" code="3404" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Scale-Factor" code="2059" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Value-Digits" required="true" max="1"/>
				<rule avp="Exponent" required="false" max="1"/>
			</data>
		</avp>

		<avp name="SDP-Answer-Timestamp" code="1275" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="SDP-Media-Component" code="843" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SDP-Media-Name" required="false" max="1"/>
				<rule avp="SDP-Media-Description" required="false"/>
				<rule avp="Local-GW-Inserted-Indication" required="false" max="1"/>
				<rule avp="IP-Realm-Default-Indication" required="false" max="1"/>
				<rule avp="Transcoder-Inserted-Indication" required="false" max="1"/>
				<rule avp="Media-Initiator-Flag" required="false" max="1"/>
				<rule avp="Media-Initiator-Party" required="false" max="1"/>
				<rule avp="TGPP-Charging-Id" required="false" max="1"/>
				<rule avp="Access-Network-Charging-Identifier-Value" required="false" max="1"/>
				<rule avp="SDP-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="SDP-Media-Description" code="845" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="SDP-Media-Name" code="844" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="SDP-Offer-Timestamp" code="1274" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="SDP-Session-Description" code="842" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="SDP-TimeStamps" code="1273" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SDP-Offer-Timestamp" required="false" max="1"/>
				<rule avp="SDP-Answer-Timestamp" required="false" max="1"/>
			</data>
		</avp>

		<avp name="SDP-Type" code="2036" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="SDP Offer"/>
				<item code="1" name="SDP Answer"/>
			</data>
		</avp>

		<avp name="Serving-Node" code="2401" must="V,M" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SGSN-Number" required="false" max="1"/>
				<rule avp="SGSN-Name" required="false" max="1"/>
				<rule avp="SGSN-Realm" required="false" max="1"/>
				<rule avp="MME-Name" required="false" max="1"/>
				<rule avp="MME-Realm" required="false" max="1"/>
				<rule avp="MSC-Number" required="false" max="1"/>
				<rule avp="TGPP-AAA-Server-Name" required="false" max="1"/>
				<rule avp="LCS-Capabilities-Sets" required="false" max="1"/>
				<rule avp="GMLC-Address" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="Session-Direction" code="2707" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="inbound"/>
				<item code="1" name="outbound"/>
			</data>
		</avp>

		<avp name="Served-Party-IP-Address" code="848" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Server-Capabilities" code="603" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Mandatory-Capability" required="false"/>
				<rule avp="Optional-Capability" required="false"/>
				<rule avp="Server-Name" required="false"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="Server-Name" code="602" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Service-Data-Container" code="2040" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="AF-Correlation-Information" required="false" max="1"/>
				<rule avp="Charging-Rule-Base-Name" required="false" max="1"/>
				<rule avp="Accounting-Input-Octets" required="false" max="1"/>
				<rule avp="Accounting-Output-Octets" required="false" max="1"/>
				<rule avp="Local-Sequence-Number" required="false" max="1"/>
				<rule avp="QoS-Information" required="false" max="1"/>
				<rule avp="Rating-Group" required="false" max="1"/>
				<rule avp="Change-Time" required="false" max="1"/>
				<rule avp="Service-Identifier" required="false" max="1"/>
				<rule avp="Service-Specific-Info" required="false" max="1"/>
				<rule avp="ADC-Rule-Base-Name" required="false" max="1"/>
				<rule avp="SGSN-Address" required="false" max="1"/>
				<rule avp="Time-First-Usage" required="false"/>
				<rule avp="Time-Last-Usage" required="false" max="1"/>
				<rule avp="Time-Usage" required="false" max="1"/>
				<rule avp="Change-Condition" required="false"/>
				<rule avp="TGPP-User-Location-Info" required="false" max="1"/>
				<rule avp="TGPP2-BSID" required="false" max="1"/>
				<rule avp="Sponsor-Identity" required="false" max="1"/>
				<rule avp="Application-Service-Provider-Identity" required="false" max="1"/>
				<rule avp="Presence-Reporting-Area-Status" required="false" max="1"/>
				<rule avp="User-CSG-Information" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Service-Id" code="855" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Service-Information" code="873" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Subscription-Id" required="false"/>
				<rule avp="AoC-Information" required="false" max="1"/>
				<rule avp="PS-Information" required="false" max="1"/>
				<rule avp="IMS-Information" required="false" max="1"/>
				<rule avp="MMS-Information" required="false" max="1"/>
				<rule avp="LCS-Information" required="false" max="1"/>
				<rule avp="PoC-Information" required="false" max="1"/>
				<rule avp="MBMS-Information" required="false" max="1"/>
				<rule avp="SMS-Information" required="false" max="1"/>
				<rule avp="VCS-Information" required="false" max="1"/>
				<rule avp="MMTel-Information" required="false" max="1"/>
				<rule avp="Service-Generic-Information" required="false" max="1"/>
				<rule avp="IM-Information" required="false" max="1"/>
				<rule avp="DCD-Information" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Service-Mode" code="2032" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Service-Specific-Data" code="863" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Service-Specific-Info" code="1249" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Service-Specific-Data" required="false" max="1"/>
				<rule avp="Service-Specific-Type" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Service-Specific-Type" code="1257" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Serving-Node-Type" code="2047" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="SGSN"/>
				<item code="1" name="PMIPSGW"/>
				<item code="2" name="GTPSGW"/>
				<item code="3" name="ePDG"/>
				<item code="4" name="hSGW"/>
				<item code="5" name="MME"/>
				<item code="6" name="TWAN"/>
			</data>
		</avp>

		<avp name="Session-Priority" code="650" must="V" may="-" must-not="M" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="PRIORITY-0"/>
				<item code="1" name="PRIORITY-1"/>
				<item code="2" name="PRIORITY-2"/>
				<item code="3" name="PRIORITY-3"/>
				<item code="4" name="PRIORITY-4"/>
			</data>
		</avp>

		<avp name="SGSN-Address" code="1228" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="SGW-Address" code="2067" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="SGW-Change" code="2065" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="ACR_Start_NOT_due_to_SGW_Change"/>
				<item code="1" name="ACR_Start_due_to_SGW_Change"/>
			</data>
		</avp>

		<avp name="SIP-Method" code="824" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="SIP-Request-Timestamp-Fraction" code="2301" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="SIP-Request-Timestamp" code="834" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="SIP-Response-Timestamp-Fraction" code="2302" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="SIP-Response-Timestamp" code="835" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="SM-Device-Trigger-Indicator" code="3407" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Not DeviceTrigger"/>
				<item code="1" name="Device Trigger"/>
			</data>
		</avp>

		<avp name="SM-Device-Trigger-Information" code="3405" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="MTC-IWF-Address" required="false" max="1"/>
				<rule avp="Reference-Number" required="false" max="1"/>
				<rule avp="Serving-Node" required="false" max="1"/>
				<rule avp="Validity-Time" required="false" max="1"/>
				<rule avp="Priority-Indication" required="false" max="1"/>
				<rule avp="Application-Port-Identifier" required="false" max="1"/>
			</data>
		</avp>

		<avp name="SM-Discharge-Time" code="2012" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="SM-Message-Type" code="2007" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="SUBMISSION"/>
				<item code="1" name="DELIVERY_REPORT"/>
				<item code="2" name="SM Service Request"/>
			</data>
		</avp>

		<avp name="SM-Protocol-Id" code="2013" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="SM-Sequence-Number" code="3408" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="SMSC-Address" code="2017" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="SMS-Information" code="2000" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SMS-Node" required="false" max="1"/>
				<rule avp="Client-Address" required="false" max="1"/>
				<rule avp="Originator-SCCP-Address" required="false" max="1"/>
				<rule avp="SMSC-Address" required="false" max="1"/>
				<rule avp="Data-Coding-Scheme" required="false" max="1"/>
				<rule avp="SM-Discharge-Time" required="false" max="1"/>
				<rule avp="SM-Message-Type" required="false" max="1"/>
				<rule avp="Originator-Interface" required="false" max="1"/>
				<rule avp="SM-Protocol-Id" required="false" max="1"/>
				<rule avp="Reply-Path-Requested" required="false" max="1"/>
				<rule avp="SM-Status" required="false" max="1"/>
				<rule avp="SM-User-Data-Header" required="false" max="1"/>
				<rule avp="Number-Of-Messages-Sent" required="false"/>
				<rule avp="SM-Sequence-Number" required="false"/>
				<rule avp="Recipient-Info" required="false"/>
				<rule avp="Originator-Received-Address" required="false" max="1"/>
				<rule avp="SM-Service-Type" required="false" max="1"/>
				<rule avp="SMS-Result" required="false" max="1"/>
				<rule avp="SM-Device-Trigger-Indicator" required="false" max="1"/>
				<rule avp="SM-Device-Trigger-Information" required="false" max="1"/>
			</data>
		</avp>

		<avp name="SMS-Node" code="2016" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="SMS Router"/>
				<item code="1" name="IP-SM-GW"/>
				<item code="2" name="SMS Router and IP-SM-GW"/>
				<item code="3" name="SMS-SC"/>
			</data>
		</avp>

		<avp name="SMS-Result" code="3409" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="SM-Service-Type" code="2029" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="VAS4SMS Short Message content processing"/>
				<item code="1" name="VAS4SMS Short Message forwarding"/>
				<item code="2" name="VAS4SMS Short Message Forwarding multiple subscriptions"/>
				<item code="3" name="VAS4SMS Short Message filtering"/>
				<item code="4" name="VAS4SMS Short Message receipt"/>
				<item code="5" name="VAS4SMS Short Message Network Storage"/>
				<item code="6" name="VAS4SMS Short Message to multiple destinations"/>
				<item code="7" name="VAS4SMS Short Message Virtual Private Network (VPN)"/>
				<item code="8" name="VAS4SMS Short Message Auto Reply"/>
				<item code="9" name="VAS4SMS Short Message Personal Signature"/>
				<item code="10" name="VAS4SMS Short Message Deferred Delivery"/>
			</data>
		</avp>

		<avp name="SM-Status" code="2014" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="SM-User-Data-Header" code="2015" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Sponsor-Identity" code="531" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="SSID" code="1524" must="V"	may="-" must-not="M,P" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Start-of-Charging" code="3419" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Start-Time" code="2041" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Status-AS-Code" code="2702" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="4xx"/>
				<item code="1" name="5xx"/>
				<item code="2" name="Timeout"/>
			</data>
		</avp>

		<avp name="Stop-Time" code="2042" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Submission-Time" code="1202" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Subscriber-Role" code="2033" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Originating"/>
				<item code="1" name="Terminating"/>
			</data>
		</avp>

		<avp name="Supplementary-Service" code="2048" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="MMTel-SService-Type" required="false" max="1"/>
				<rule avp="Service-Mode" required="false" max="1"/>
				<rule avp="Number-Of-Diversions" required="false" max="1"/>
				<rule avp="Associated-Party-Address" required="false" max="1"/>
				<rule avp="Service-Id" required="false" max="1"/>
				<rule avp="Change-Time" required="false" max="1"/>
				<rule avp="Number-Of-Participants" required="false" max="1"/>
				<rule avp="Participant-Action-Type" required="false" max="1"/>
				<rule avp="CUG-Information" required="false" max="1"/>
				<rule avp="AoC-Information" required="false" max="1"/>
			</data>
		</avp>

		<avp name="TAD-Identifier" code="2717" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="CS"/>
				<item code="1" name="PS"/>
			</data>
		</avp>

		<avp name="Talk-Burst-Exchange" code="1255" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="PoC-Change-Time" required="true" max="1"/>
				<rule avp="Number-Of-Talk-Bursts" required="false" max="1"/>
				<rule avp="Talk-Burst-Volume" required="false" max="1"/>
				<rule avp="Talk-Burst-Time" required="false" max="1"/>
				<rule avp="Number-Of-Received-Talk-Bursts" required="false" max="1"/>
				<rule avp="Received-Talk-Burst-Volume" required="false" max="1"/>
				<rule avp="Received-Talk-Burst-Time" required="false" max="1"/>
				<rule avp="Number-Of-Participants" required="false" max="1"/>
				<rule avp="PoC-Change-Condition" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Talk-Burst-Time" code="1286" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Talk-Burst-Volume" code="1287" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Tariff-Information" code="2060" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Current-Tariff" required="true" max="1"/>
				<rule avp="Tariff-Time-Change" required="false" max="1"/>
				<rule avp="Next-Tariff" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Tariff-XML" code="2306" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="TDF-IP-Address" code="1091" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Address"/>
		</avp>

		<avp name="Teleservice" code="3413" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Terminal-Information" code="1401" must="V,M"	may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="IMEI" required="false" max="1"/>
				<rule avp="TGPP2-MEID" required="false" max="1"/>
				<rule avp="Software-Version" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>

		<avp name="IMEI" code="1402" must="M,V" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String" />
		</avp>

		<avp name="Software-Version" code="1403" must="M,V" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String" />
		</avp>

		<avp name="Terminating-IOI" code="840" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Time-First-Usage" code="2043" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Time-Last-Usage" code="2044" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="Time-Quota-Mechanism" code="1270" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Time-Quota-Type" required="true" max="1"/>
				<rule avp="Base-Time-Interval" required="true" max="1"/>
			</data>
		</avp>

		<avp name="Time-Quota-Threshold" code="868" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Time-Quota-Type" code="1271" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="DISCRETE_TIME_PERIOD"/>
				<item code="1" name="CONTINUOUS_TIME_PERIOD"/>
			</data>
		</avp>

		<avp name="Time-Stamps" code="833" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SIP-Request-Timestamp" required="false" max="1"/>
				<rule avp="SIP-Response-Timestamp" required="false" max="1"/>
				<rule avp="SIP-Request-Timestamp-Fraction" required="false" max="1"/>
				<rule avp="SIP-Response-Timestamp-Fraction" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Time-Usage" code="2045" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="TMGI" code="900" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Token-Text" code="1215" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Total-Number-Of-Messages-Exploded" code="2113" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Total-Number-Of-Messages-Sent" code="2114" must="V,M"	may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Traffic-Data-Volumes" code="2046" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="QoS-Information" required="false" max="1"/>
				<rule avp="Accounting-Input-Octets" required="false" max="1"/>
				<rule avp="Accounting-Output-Octets" required="false" max="1"/>
				<rule avp="Change-condition" required="false" max="1"/>
				<rule avp="Change-Time" required="false" max="1"/>
				<rule avp="TGPP-User-Location-Info" required="false" max="1"/>
				<rule avp="TGPP-Charging-Id" required="false" max="1"/>
				<rule avp="Presence-Reporting-Area-Status" required="false" max="1"/>
				<rule avp="User-CSG-Information" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Transcoder-Inserted-Indication" code="2605" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Transcoder Not Inserted"/>
				<item code="1" name="Transcoder Inserted"/>
			</data>
		</avp>

		<avp name="Transit-IOI-List" code="2701" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Trigger" code="1264" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Trigger-Type" required="false"/>
			</data>
		</avp>

		<avp name="Trigger-Type" code="870" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="1" name="CHANGE_IN_SGSN_IP_ADDRESS"/>
				<item code="2" name="CHANGE_IN_QOS"/>
				<item code="3" name="CHANGE_IN_LOCATION"/>
				<item code="4" name="CHANGE_IN_RAT"/>
				<item code="5" name="CHANGE_IN_UE_TIMEZONE"/>
				<item code="10" name="CHANGEINQOS_TRAFFIC_CLASS"/>
				<item code="11" name="CHANGEINQOS_RELIABILITY_CLASS"/>
				<item code="12" name="CHANGEINQOS_RELIABILITY_CLASS"/>
				<item code="13" name="CHANGEINQOS_PEAK_THROUGHPUT"/>
				<item code="14" name="CHANGEINQOS_PRECEDENCE_CLASS"/>
				<item code="15" name="CHANGEINQOS_MEAN_THROUGHPUT"/>
				<item code="16" name="CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_UPLINK"/>
				<item code="17" name="CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_DOWNLINK"/>
				<item code="18" name="CHANGEINQOS_RESIDUAL_BER"/>
				<item code="19" name="CHANGEINQOS_SDU_ERROR_RATIO"/>
				<item code="20" name="CHANGEINQOS_TRANSFER_DELAY"/>
				<item code="21" name="CHANGEINQOS_TRAFFIC_HANDLING_PRIORITY"/>
				<item code="22" name="CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_UPLINK"/>
				<item code="23" name="CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_DOWNLINK"/>
				<item code="24" name="CHANGEINQOS_APN_AGGREGATE_MAXIMUM_BIT_RATE"/>
				<item code="30" name="CHANGEINLOCATION_MCC"/>
				<item code="31" name="CHANGEINLOCATION_MNC"/>
				<item code="32" name="CHANGEINLOCATION_RAC"/>
				<item code="33" name="CHANGEINLOCATION_LAC"/>
				<item code="34" name="CHANGEINLOCATION_CellId"/>
				<item code="35" name="CHANGEINLOCATION_TAC"/>
				<item code="36" name="CHANGEINLOCATION_ECGI"/>
				<item code="40" name="CHANGE_IN_MEDIA_COMPOSITION"/>
				<item code="50" name="CHANGE_IN_PARTICIPANTS_NMB"/>
				<item code="51" name="CHANGE_IN_ THRSHLD_OF_PARTICIPANTS_NMB"/>
				<item code="52" name="CHANGE_IN_USER_PARTICIPATING_TYPE"/>
				<item code="60" name="CHANGE_IN_SERVICE_CONDITION"/>
				<item code="61" name="CHANGE_IN_SERVING_NODE"/>
				<item code="70" name="CHANGE_IN_USER_CSG_INFORMATION"/>
				<item code="71" name="CHANGE_IN_HYBRID_SUBSCRIBED_USER_CSG_INFORMATION"/>
				<item code="72" name="CHANGE_IN_HYBRID_UNSUBSCRIBED_USER_CSG_INFORMATION"/>
				<item code="73" name="CHANGE_OF_UE_PRESENCE_IN_PRESENCE_REPORTING_AREA"/>
			</data>
		</avp>

		<avp name="Trunk-Group-Id" code="851" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Incoming-Trunk-Group-Id" required="false" max="1"/>
				<rule avp="Outgoing-Trunk-Group-Id" required="false" max="1"/>
			</data>
		</avp>

		<avp name="TWAN-User-Location-Info" code="2714" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="SSID" required="true" max="1"/>
				<rule avp="BSSID" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Type-Number" code="1204" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="Unit-Cost" code="2061" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Value-Digits" required="true" max="1"/>
				<rule avp="Exponent" required="false" max="1"/>
			</data>
		</avp>

		<avp name="Unit-Quota-Threshold" code="1226" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="User-CSG-Information" code="2319" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="CSG-Id" required="true" max="1"/>
				<rule avp="CSG-Access-Mode" required="true" max="1"/>
				<rule avp="CSG-Membership-Indication" required="false" max="1"/>
			</data>
		</avp>

		<avp name="User-Data" code="606" must="V,M"	may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="User-Location-Info-Time" code="2812" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Time"/>
		</avp>

		<avp name="User-Participating-Type" code="1279" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Enumerated">
				<item code="0" name="Normal"/>
				<item code="1" name="NW PoC Box"/>
				<item code="2" name="UE PoC Box"/>
			</data>
		</avp>

		<avp name="User-Session-Id" code="830" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="VAS-Id" code="1102" must="V,M"	may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="VASP-Id" code="1101" must="V,M"	may="-" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="UTF8String"/>
		</avp>

		<avp name="VCS-Information" code="3410" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Grouped">
				<rule avp="Bearer-Capability" required="false" max="1"/>
				<rule avp="Network-Call-Reference-Number" required="false" max="1"/>
				<rule avp="MSC-Address" required="false" max="1"/>
				<rule avp="Basic-Service-Code" required="false" max="1"/>
				<rule avp="ISUP-Location-Number" required="false" max="1"/>
				<rule avp="VLR-Number" required="false" max="1"/>
				<rule avp="Forwarding-Pending" required="false" max="1"/>
				<rule avp="ISUP-Release-Cause" required="false" max="1"/>
				<rule avp="Start-Time" required="false" max="1"/>
				<rule avp="Start-of-Charging" required="false" max="1"/>
				<rule avp="Stop-Time" required="false" max="1"/>
				<rule avp="PS-Free-Format-Data" required="false" max="1"/>
			</data>
		</avp>

		<avp name="VLR-Number" code="3420" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="Volume-Quota-Threshold" code="869" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="SGSN-Number" code="1489" must="V,M" may-encrypt="N" vendor-id="10415">
			<data type="OctetString"/>
		</avp>

		<avp name="GMLC-Address" code="2405" must="V,M" may-encrypt="N" vendor-id="10415">
			<data type="Address"/>
		</avp>

    <avp name="Supported-Features" code="628" vendor-id="10415" must="V" may="M" may-encrypt="N">
      <data type="Grouped">
        <rule avp="Vendor-Id" required="true" max="1"/>
        <rule avp="Feature-List-ID" required="true" max="1"/>
        <rule avp="Feature-List" required="true" max="1"/>
      </data>
    </avp>

    <avp name="Feature-List-ID" code="629" must="V" must_not="M" may-encrypt="N" vendor-id="10415">
      <data type="Unsigned32"/>
    </avp>

    <avp name="Feature-List" code="630" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
      <data type="Unsigned32"/>
    </avp>

    <avp name="APN-Aggregate-Max-Bitrate-DL" code="1040" must="V" must-not="M" may-encrypt="Y" vendor-id="10415">
      <data type="Unsigned32"/>
    </avp>

    <avp name="APN-Aggregate-Max-Bitrate-UL" code="1041" must="V" must-not="M" may-encrypt="Y" vendor-id="10415">
      <data type="Unsigned32"/>
    </avp>

    <avp name="Extended-APN-AMBR-DL" code="2848" must="V" must-not="M" may= "P" may-encrypt="Y" vendor-id="10415">
      <data type="Unsigned32"/>
    </avp>

    <avp name="Extended-APN-AMBR-UL" code="2849" must="V" must-not="M" may="P" may-encrypt="Y" vendor-id="10415">
      <data type="Unsigned32"/>
    </avp>

	</application>
</diameter>`

var tgpps13XML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
         <application id="16777252" type="auth" name="TGPP S13">
         <vendor id="10415" name="TGPP"/>
         <command code="324" short="EC" name="ME-Identity-Check">
                         <request>
                                 <rule avp="Session-Id" required="true" max="1" />
                                 <rule avp="DRMP" required="false" max="1" />
                                 <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
                                 <rule avp="Auth-Session-State" required="true" max="1" />
                                 <rule avp="Origin-Host" required="true" max="1" />
                                 <rule avp="Origin-Realm" required="true" max="1" />
                                 <rule avp="Destination-Host" required="false" max="1" />
                                 <rule avp="Destination-Realm" required="true" max="1" />
                                 <rule avp="Terminal-Information" required="true" max="1" />
                                 <rule avp="User-Name" required="false" max="1" />
                                 <rule avp="AVP" required="false" />
                                 <rule avp="Proxy-Info" required="false" />
                                 <rule avp="Route-Record" required="false" />
                         </request>
                         <answer>
                                 <rule avp="Session-Id" required="true" max="1" />
                                 <rule avp="DRMP" required="false" max="1" />
                                 <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
                                 <rule avp="Result-Code" required="false" max="1" />
                                 <rule avp="Experimental-Result" required="false" max="1" />
                                 <rule avp="Auth-Session-State" required="true" max="1" />
                                 <rule avp="Origin-Host" required="true" max="1" />
                                 <rule avp="Origin-Realm" required="true" max="1" />
                                 <rule avp="Equipment-Status" required="false" max="1" />
                                 <rule avp="AVP" required="false" />
                                 <rule avp="Failed-AVP" required="false" max="1" />
                                 <rule avp="Proxy-Info" required="false" />
                                 <rule avp="Route-Record" required="false" />
                        </answer>
                </command>

                <avp name="Session-Id" code="263" must="M" may="P" must-not="V" may-encrypt="Y">
                        <data type="UTF8String"   />
                </avp>

                <avp name="DRMP" code="301" must-not="V">
                        <data type="Enumerated">
                                <item code="0" name="PRIORITY_0"/>
                                <item code="1" name="PRIORITY_1"/>
                                <item code="2" name="PRIORITY_2"/>
                                <item code="3" name="PRIORITY_3"/>
                                <item code="4" name="PRIORITY_4"/>
                                <item code="5" name="PRIORITY_5"/>
                                <item code="6" name="PRIORITY_6"/>
                                <item code="7" name="PRIORITY_7"/>
                                <item code="8" name="PRIORITY_8"/>
                                <item code="9" name="PRIORITY_9"/>
                                <item code="10" name="PRIORITY_10"/>
                                <item code="11" name="PRIORITY_11"/>
                                <item code="12" name="PRIORITY_12"/>
                                <item code="13" name="PRIORITY_13"/>
                                <item code="14" name="PRIORITY_14"/>
                                <item code="15" name="PRIORITY_15"/>
                        </data>
                </avp>

                <avp name="Vendor-Specific-Application-Id" code="260" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Grouped">
                                <rule avp="Vendor-ID" required="false" max="1"/>
                                <rule avp="Auth-Application-Id" required="true" max="1"/>
                                <rule avp="Acct-Application-Id" required="true" max="1"/>
                        </data>
                </avp>

                 <avp name="Result-Code" code="268" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Unsigned32"/>
                </avp>

                <avp name="Vendor-ID" code="266" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Unsigned32"/>
                </avp>

                <avp name="Auth-Application-Id" code="258" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Unsigned32"/>
                </avp>

                <avp name="Acct-Application-Id" code="259" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Unsigned32"/>
                </avp>

                <avp name="Auth-Session-State" code="277" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Enumerated">
                                <item code="0" name="STATE_MAINTAINED"/>
                                <item code="1" name="NO_STATE_MAINTAINED"/>
                        </data>
                </avp>

                <avp name="Origin-Host" code="264" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="DiameterIdentity"/>
                </avp>
                <avp name="Origin-Realm" code="296" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="DiameterIdentity"/>
                </avp>

                <avp name="Destination-Host" code="293" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="DiameterIdentity"/>
                </avp>

                <avp name="Destination-Realm" code="283" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="DiameterIdentity"/>
                </avp>

                <avp name="Terminal-Information" code="1401" must="M,V" may-encrypt="N" vendor-id="10415">
                <!-- 3GPP TS 29.272 Section 7.3.3 -->
                        <data type="Grouped">
                           <rule avp="IMEI" required="false" max="1"/>
                           <rule avp="TGPP2-MEID" required="false" max="1"/>
                           <rule avp="Software-Version" required="false" max="1"/>
                           <rule avp="AVP" required="false"/>
                        </data>
                </avp>

                <avp name="IMEI" code="1402" must="M,V" may-encrypt="N" vendor-id="10415">
                        <data type="UTF8String" />
                </avp>

                <avp name="_3GPP2-MEID" code="1471" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
                        <data type="OctetString"  />
                </avp>

                <avp name="Software-Version" code="1403" must="M,V" may-encrypt="N" vendor-id="10415">
                        <data type="UTF8String" />
                </avp>

                <avp name="User-Name" code="1" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="10415">
                        <data type="UTF8String"   />
                </avp>

                <avp name="Proxy-Info" code="284" must="M" may="-" must-not="P,V" may-encrypt="-">
                        <data type="Grouped">
                                <rule avp="Proxy-Host" required="true" max="1"/>
                                <rule avp="Proxy-State" required="true" max="1"/>
                        </data>
                </avp>

                <avp name="Proxy-Host" code="280" must="M" may="-" must-not="P,V" may-encrypt="-">
                        <data type="DiameterIdentity"/>
                </avp>

                <avp name="Proxy-State" code="33" must="M" may="-" must-not="P,V" may-encrypt="-">
                        <data type="OctetString"/>
                </avp>

                 <avp name="Route-Record" code="282" must="M" may="-" must-not="P,V" may-encrypt="-">
                        <data type="DiameterIdentity"/>
                </avp>

                <avp name="Experimental-Result" code="297" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Grouped">
                                <rule avp="Vendor-ID" required="true" max="1"/>
                                <rule avp="Experimental-Result-Code" required="true" max="1"/>
                        </data>
                </avp>

                <avp name="Equipment-Status" code="1445" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
                        <data type="Enumerated">
                           <item code="0" name="PERMITTEDLISTED"/>
                           <item code="1" name="PROHIBITEDLISTED"/>
                        </data>
                </avp>

                <avp name="Failed-AVP" code="279" must="M" may="P" must-not="V" may-encrypt="-">
                        <data type="Grouped"/>
                </avp>
        </application>
</diameter>`

var tgpps6aXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
    <!--
        3GPP TS 29.272
        See: http://www.etsi.org/deliver/etsi_ts/129200_129299/129272/12.06.00_60/ts_129272v120600p.pdf
    -->
    <application id="16777251" type="auth" name="TGPP S6A">
        <vendor id="10415" name="TGPP"/>
        <command code="316" short="UL" name="Update-Location">
            <request>
                <rule avp="Session-Id" required="true" max="1"/>
	        	<rule avp="DRMP" required="false" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Host" required="false" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
	        	<rule avp="OC-Supported-Features" required="false" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="Terminal-Information" required="false" max="1"/>
                <rule avp="RAT-Type" required="true" max="1"/>
                <rule avp="ULR-Flags" required="true" max="1"/>
                <rule avp="UE-SRVCC-Capability" required="false" max="1"/>
                <rule avp="Visited-PLMN-Id" required="true" max="1"/>
                <rule avp="SGSN-Number" required="false" max="1"/>
                <rule avp="Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions" required="false" max="1"/>
                <rule avp="GMLC-Address" required="false" max="1"/>
                <rule avp="Active-APN" required="false"/>
		<rule avp="Equivalent-PLMN-List" required="false"/>
		<rule avp="MME-Number-for-MT-SMS" required="false"/>
		<rule avp="SMS-Register-Request" required="false"/>
		<rule avp="SGs-MME-Identity" required="false"/>
		<rule avp="Coupled-Node-Diameter-ID" required="false"/>
		<rule avp="Adjacent-PLMNs" required="false"/>
		<rule avp="Supported-Services" required="false"/>
                <rule avp="AVP" required="false"/>
                <rule avp="Proxy-Info" required="false"/>
                <rule avp="Route-Record" required="false"/>
            </request>
            <answer>
                <rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
                <rule avp="Result-Code" required="false" max="1"/>
                <rule avp="Error-Diagnostic" required="false" max="1"/>
                <rule avp="Experimental-Result" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
		<rule avp="OC-Supported-Features" required="false" max="1"/>
		<rule avp="OC-OLR" required="false" max="1"/>
		<rule avp="Load" required="false"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="ULA-Flags" required="false" max="1"/>
                <rule avp="Subscription-Data" required="false" max="1"/>
		<rule avp="Reset-ID" required="false"/>
                <rule avp="AVP" required="false"/>
                <rule avp="Failed-AVP" required="false"/>
                <rule avp="Proxy-Info" required="false"/>
                <rule avp="Route-Record" required="false"/>
            </answer>
        </command>

        <command code="317" short="CL" name="Cancel-Location">
            <request>
                <rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Host" required="true" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="Cancellation-Type" required="true" max="1"/>
                <rule avp="CLR-Flags" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
                <rule avp="Proxy-Info" required="false"/>
                <rule avp="Route-Record" required="false"/>
            </request>
            <answer>
                <rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="Result-Code" required="false" max="1"/>
                <rule avp="Experimental-Result" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
                <rule avp="Failed-AVP" required="false"/>
                <rule avp="Proxy-Info" required="false"/>
                <rule avp="Route-Record" required="false"/>
            </answer>
        </command>

        <command code="318" short="AI" name="Authentication-Information">
            <request>
                <rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Host" required="false" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
		<rule avp="OC-Supported-Features" required="false" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="Requested-EUTRAN-Authentication-Info" required="false" max="1"/>
                <rule avp="Requested-UTRAN-GERAN-Authentication-Info" required="false" max="1"/>
                <rule avp="Visited-PLMN-Id" required="true" max="1"/>
                <rule avp="AIR-Flags" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
                <rule avp="Proxy-Info" required="false"/>
                <rule avp="Route-Record" required="false"/>
            </request>
            <answer>
                <rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
                <rule avp="Result-Code" required="false" max="1"/>
                <rule avp="Experimental-Result" required="false" max="1"/>
                <rule avp="Error-Diagnostic" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
		<rule avp="OC-Supported-Features" required="false" max="1"/>
                <rule avp="OC-OLR" required="false" max="1" />
		<rule avp="Load" required="false"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="Authentication-Info" required="true" max="1"/>
		<rule avp="UE-Usage-Type" required="false"/>
                <rule avp="AVP" required="false"/>
                <rule avp="Failed-AVP" required="false"/>
                <rule avp="Proxy-Info" required="false"/>
                <rule avp="Route-Record" required="false"/>
            </answer>
        </command>

	<command code="319" short="ID" name="Insert-Subscriber-Data">
	    <request>
		<rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
		<rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
		<rule avp="Auth-Session-State" required="true" max="1"/>
		<rule avp="Origin-Host" required="true" max="1"/>
		<rule avp="Origin-Realm" required="true" max="1"/>
		<rule avp="Destination-Host" required="true" max="1"/>
		<rule avp="Destination-Realm" required="true" max="1"/>
		<rule avp="User-Name" required="true" max="1"/>
		<rule avp="Supported-Features" required="false"/>
		<rule avp="Subscription-Data" required="true" max="1"/>
		<rule avp="IDR-Flags" required="false" max="1"/>
		<rule avp="Reset-ID" required="false"/>
		<rule avp="AVP" required="false"/>
		<rule avp="Proxy-Info" required="false"/>
		<rule avp="Route-Record" required="false"/>
	    </request>
	    <answer>
		<rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
		<rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
		<rule avp="Supported-Features" required="false"/>
		<rule avp="Result-Code" required="false" max="1"/>
		<rule avp="Experimental-Result" required="false" max="1"/>
		<rule avp="Auth-Session-State" required="true" max="1"/>
		<rule avp="Origin-Host" required="true" max="1"/>
		<rule avp="Origin-Realm" required="true" max="1"/>
		<rule avp="IMS-Voice-Over-PS-Sessions-Supported" required="false"/>
		<rule avp="Last-UE-Activity-Time" required="false"/>
		<rule avp="RAT-Type" required="false" max="1"/>
		<rule avp="IDA-Flags" required="false" max="1"/>
		<rule avp="EPS-User-State" required="false" max="1"/>
		<rule avp="EPS-Location-Information" required="false" max="1"/>
		<rule avp="Local-Time-Zone" required="false" max="1"/>
		<rule avp="Supported-Services" required="false"/>
		<rule avp="Monitoring-Event-Report" required="false"/>
		<rule avp="Monitoring-Event-Config-Status" required="false"/>
		<rule avp="AVP" required="false"/>
                <rule avp="Failed-AVP" required="false"/>
		<rule avp="Proxy-Info" required="false"/>
		<rule avp="Route-Record" required="false"/>
	     </answer>
	</command>

	<command code="320" short="DS" name="Delete-Subscriber-Data">
	    <request>
		<rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
		<rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
		<rule avp="Auth-Session-State" required="true" max="1"/>
		<rule avp="Origin-Host" required="true" max="1"/>
		<rule avp="Origin-Realm" required="true" max="1"/>
		<rule avp="Destination-Host" required="true" max="1"/>
		<rule avp="Destination-Realm" required="true" max="1"/>
		<rule avp="User-Name" required="true" max="1"/>
		<rule avp="Supported-Features" required="false"/>
		<rule avp="DSR-Flags" required="true" max="1"/>
		<rule avp="SCEF-ID" required="false"/>
                <rule avp="Trace-Reference" required="false" max="1"/>
                <rule avp="Context-Identifier" required="false" max="1" />
		<rule avp="TS-Code" required="false"/>
		<rule avp="SS-Code" required="false"/>
		<rule avp="eDRX-Related-RAT" required="false" max="1"/>
		<rule avp="External-Identifier" required="false"/>
		<rule avp="AVP" required="false"/>
		<rule avp="Proxy-Info" required="false"/>
		<rule avp="Route-Record" required="false"/>
	    </request>
	    <answer>
		<rule avp="Session-Id" required="true" max="1"/>
		<rule avp="DRMP" required="false" max="1"/>
		<rule avp="Vendor-Specific-Application-Id" required="false" max="1"/>
		<rule avp="Supported-Features" required="false"/>
		<rule avp="Result-Code" required="false" max="1"/>
		<rule avp="Experimental-Result" required="false" max="1"/>
		<rule avp="Auth-Session-State" required="true" max="1"/>
		<rule avp="Origin-Host" required="true" max="1"/>
		<rule avp="Origin-Realm" required="true" max="1"/>
		<rule avp="DSA-Flags" required="false" max="1"/>
		<rule avp="AVP" required="false"/>
                <rule avp="Failed-AVP" required="false"/>
		<rule avp="Proxy-Info" required="false"/>
		<rule avp="Route-Record" required="false"/>
	     </answer>
	</command>

        <command code="321" short="PU" name="Purge-UE">
            <request>
                <rule avp="Session-Id" required="true" max="1" />
                <rule avp="DRMP" required="false" max="1" />
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
                <rule avp="Auth-Session-State" required="true" max="1" />
                <rule avp="Origin-Host" required="true" max="1" />
                <rule avp="Origin-Realm" required="true" max="1" />
                <rule avp="Destination-Host" required="false" max="1" />
                <rule avp="Destination-Realm" required="true" max="1" />
                <rule avp="User-Name" required="true" max="1" />
                <rule avp="OC-Supported-Features" required="false" max="1" />
                <rule avp="PUR-Flags" required="false" max="1" />
                <rule avp="Supported-Features" required="false" />
                <rule avp="EPS-Location-Information" required="false" max="1" />
                <rule avp="AVP" required="false"/>
                <rule avp="Proxy-Info" required="false" />
                <rule avp="Route-Record" required="false" />
            </request>
            <answer>
                <rule avp="Session-Id" required="true" max="1" />
                <rule avp="DRMP" required="false" max="1" />
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
                <rule avp="Supported-Features" required="false" />
                <rule avp="Result-Code" required="false" max="1" />
                <rule avp="Experimental-Result" required="false" max="1" />
                <rule avp="Auth-Session-State" required="true" max="1" />
                <rule avp="Origin-Host" required="true" max="1" />
                <rule avp="Origin-Realm" required="true" max="1" />
                <rule avp="OC-Supported-Features" required="false" max="1" />
                <rule avp="OC-OLR" required="false" max="1" />
                <rule avp="Load" required="false" />
                <rule avp="PUA-Flags" required="false" max="1" />
                <rule avp="AVP" required="false"/>
                <rule avp="Failed-AVP" required="false" max="1" />
                <rule avp="Proxy-Info" required="false" />
                <rule avp="Route-Record" required="false" />
            </answer>
        </command>

        <command code="323" short="NO" name="Notify">
            <request>
                <rule avp="Session-Id" required="true" max="1" />
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
                <rule avp="DRMP" required="false" max="1" />
                <rule avp="Auth-Session-State" required="true" max="1" />
                <rule avp="Origin-Host" required="true" max="1" />
                <rule avp="Origin-Realm" required="true" max="1" />
                <rule avp="Destination-Host" required="false" max="1" />
                <rule avp="Destination-Realm" required="true" max="1" />
                <rule avp="User-Name" required="true" max="1" />
                <rule avp="OC-Supported-Features" required="false" max="1" />
                <rule avp="Supported-Features" required="false" />
                <rule avp="Terminal-Information" required="false" max="1" />
                <rule avp="MIP6-Agent-Info" required="false" max="1" />
                <rule avp="Visited-Network-Identifier" required="false" max="1" />
                <rule avp="Context-Identifier" required="false" max="1" />
                <rule avp="Service-Selection" required="false" max="1" />
                <rule avp="Alert-Reason" required="false" max="1" />
                <rule avp="UE-SRVCC-Capability" required="false" max="1" />
                <rule avp="NOR-Flags" required="false" max="1" />
                <rule avp="Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions" required="false" max="1" />
                <rule avp="Maximum-UE-Availability-Type" required="false" max="1" />
                <rule avp="Monitoring-Event-Config-Status" required="false" />
                <rule avp="Emergency-Services" required="false" max="1" />
                <rule avp="AVP" required="false"/>
                <rule avp="Proxy-Info" required="false" />
                <rule avp="Route-Record" required="false" />
            </request>
            <answer>
                <rule avp="Session-Id" required="true" max="1" />
                <rule avp="DRMP" required="false" max="1" />
                <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
                <rule avp="Result-Code" required="false" max="1" />
                <rule avp="Experimental-Result" required="false" max="1" />
                <rule avp="Auth-Session-State" required="true" max="1" />
                <rule avp="Origin-Host" required="true" max="1" />
                <rule avp="Origin-Realm" required="true" max="1" />
                <rule avp="OC-Supported-Features" required="false" max="1" />
                <rule avp="OC-OLR" required="false" max="1" />
                <rule avp="Load" required="false" />
                <rule avp="Supported-Features" required="false" />
                <rule avp="AVP" required="false"/>
                <rule avp="Failed-AVP" required="false" max="1" />
                <rule avp="Proxy-Info" required="false" />
                <rule avp="Route-Record" required="false" />
            </answer>
        </command>
	<command code="322" short="RS" name="Reset">
    <request>
        <rule avp="Session-Id" required="true" max="1" />
        <rule avp="DRMP" required="false" max="1" />
        <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
        <rule avp="Auth-Session-State" required="true" max="1" />
        <rule avp="Origin-Host" required="true" max="1" />
        <rule avp="Origin-Realm" required="true" max="1" />
        <rule avp="Destination-Host" required="false" max="1" />
        <rule avp="Destination-Realm" required="true" max="1" />
        <rule avp="Supported-Features" required="false" />
        <rule avp="User-Id" required="false" />
        <rule avp="Proxy-Info" required="false" />
        <rule avp="Route-Record" required="false" />
        <rule avp="Reset-ID" required="false" />
        <rule avp="Subscription-Data" required="false" max="1" />
        <rule avp="Subscription-Data-Deletion" required="false" max="1" />
    </request>
	<answer>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" />
    <rule avp="Vendor-Specific-Application-Id" required="false" max="1" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="false" max="1" />
    <rule avp="Destination-Realm" required="false" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="Reset-ID" required="false" />
    <rule avp="Result-Code" required="false" max="1" />
    <rule avp="Experimental-Result" required="false" max="1" />
    <rule avp="Failed-AVP" required="false" max="1" />
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</answer>
        </command>
        <avp name="Subscription-Data" code="1400" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="Subscriber-Status" required="false" max="1"/>
                <rule avp="MSISDN" required="false" max="1"/>
                <rule avp="A-MSISDN" required="false" max="1"/>
                <rule avp="STN-SR" required="false" max="1"/>
                <rule avp="ICS-Indicator" required="false" max="1"/>
                <rule avp="Network-Access-Mode" required="false" max="1"/>
                <rule avp="Operator-Determined-Barring" required="false" max="1"/>
                <rule avp="HPLMN-ODB" required="false" max="1"/>
                <rule avp="Regional-Subscription-Zone-Code" required="false" max="10"/>
                <rule avp="Access-Restriction-Data" required="false" max="1"/>
                <rule avp="APN-OI-Replacement" required="false" max="1"/>
                <rule avp="LCS-Info" required="false" max="1"/>
                <rule avp="Teleservice-List" required="false" max="1"/>
                <rule avp="Call-Barring-Info" required="false"/>
                <rule avp="TGPP-Charging-Characteristics" required="false" max="1"/>
                <rule avp="AMBR" required="false" max="1"/>
                <rule avp="APN-Configuration-Profile" required="false" max="1"/>
                <rule avp="RAT-Frequency-Selection-Priority-ID" required="false" max="1"/>
                <rule avp="Trace-Data" required="false" max="1"/>
                <rule avp="GPRS-Subscription-Data" required="false" max="1"/>
                <rule avp="CSG-Subscription-Data" required="false"/>
                <rule avp="Roaming-Restricted-Due-To-Unsupported-Feature" required="false" max="1"/>
                <rule avp="Subscribed-Periodic-RAU-TAU-Timer" required="false" max="1"/>
                <rule avp="MPS-Priority" required="false" max="1"/>
                <rule avp="VPLMN-LIPA-Allowed" required="false" max="1"/>
                <rule avp="Relay-Node-Indicator" required="false" max="1"/>
                <rule avp="MDT-User-Consent" required="false" max="1"/>
		<rule avp="Subscribed-VSRVCC" required="false" max="1"/>
		<rule avp="ProSe-Subscription-Data" required="false"/>
		<rule avp="Subscription-Data-Flags" required="false"/>
		<rule avp="Adjacent-Access-Restriction-Data" required="false"/>
		<rule avp="DL-Buffering-Suggested-Packet-Count" required="false"/>
		<rule avp="IMSI-Group-Id" required="false"/>
		<rule avp="UE-Usage-Type" required="false"/>
		<rule avp="AESE-Communication-Pattern" required="false"/>
		<rule avp="Monitoring-Event-Configuration" required="false"/>
		<rule avp="Emergency-Info" required="false"/>
		<rule avp="V2X-Subscription-Data" required="false"/>
		<rule avp="V2X-Subscription-Data-Nr" required="false"/>
		<rule avp="eDRX-Cycle-Length" required="false"/>
		<rule avp="External-Identifier" required="false"/>
		<rule avp="Active-Time" required="false"/>
		<rule avp="Service-Gap-Time" required="false"/>
		<rule avp="Broadcast-Location-Assistance-Data-Types" required="false"/>
		<rule avp="Aerial-UE-Subscription-Information" required="false"/>
		<rule avp="Core-Network-Restrictions" required="false"/>
		<rule avp="Paging-Time-Window" required="false"/>
		<rule avp="Subscribed-ARPI" required="false"/>
		<rule avp="IAB-Operation-Permission" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Subscriber-Status" code="1424" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="SERVICE_GRANTED"/>
                <item code="1" name="OPERATOR_DETERMINED_BARRING"/>
            </data>
        </avp>

        <avp name="STN-SR" code="1433" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="ICS-Indicator" code="1491" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="FALSE"/>
                <item code="1" name="TRUE"/>
            </data>
        </avp>

        <avp name="Network-Access-Mode" code="1417" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="PACKET_AND_CIRCUIT"/>
                <item code="1" name="RESERVED"/>
                <item code="2" name="ONLY_PACKET"/>
            </data>
        </avp>

        <avp name="Operator-Determined-Barring" code="1425" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="HPLMN-ODB" code="1418" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Regional-Subscription-Zone-Code" code="1446" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Access-Restriction-Data" code="1426" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="APN-OI-Replacement" code="1427" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="UTF8String"/>
        </avp>

        <avp name="LCS-Info" code="1473" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="GMLC-Number" required="false"/>
                <rule avp="LCS-PrivacyException" required="false"/>
                <rule avp="MO-LR" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="GMLC-Number" code="1474" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="LCS-PrivacyException" code="1475" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="SS-Code" required="true" max="1"/>
                <rule avp="SS-Status" required="true" max="1"/>
                <rule avp="Notification-To-UE-User" required="false" max="1"/>
                <rule avp="External-Client" required="false"/>
                <rule avp="PLMN-Client" required="false"/>
                <rule avp="Service-Type" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="SS-Code" code="1476" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="SS-Status" code="1477" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Notification-To-UE-User" code="1478" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="NOTIFY_LOCATION_ALLOWED"/>
                <item code="1" name="NOTIFYANDVERIFY_LOCATION_ALLOWED_IF_NO_RESPONSE"/>
                <item code="2" name="NOTIFYANDVERIFY_LOCATION_NOT_ALLOWED_IF_NO_RESPONSE"/>
                <item code="3" name="LOCATION_NOT_ALLOWED"/>
            </data>
        </avp>

        <avp name="External-Client" code="1479" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Client-Identity" required="true" max="1"/>
                <rule avp="GMLC-Restriction" required="false" max="1"/>
                <rule avp="Notification-To-UE-User" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Client-Identity" code="1480" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="GMLC-Restriction" code="1481" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="GMLC_LIST"/>
                <item code="1" name="HOME_COUNTRY"/>
            </data>
        </avp>

        <avp name="PLMN-Client" code="1482" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="BROADCAST_SERVICE"/>
                <item code="1" name="O_AND_M_HPLMN"/>
                <item code="2" name="O_AND_M_VPLMN"/>
                <item code="3" name="ANONYMOUS_LOCATION"/>
                <item code="3" name="TARGET_UE_SUBSCRIBED_SERVICE"/>
            </data>
        </avp>

        <avp name="Service-Type" code="1483" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="ServiceTypeIdentity" required="true" max="1"/>
                <rule avp="GMLC-Restriction" required="false" max="1"/>
                <rule avp="Notification-To-UE-User" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="ServiceTypeIdentity" code="1484" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="MO-LR" code="1485" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="SS-Code" required="true" max="1"/>
                <rule avp="SS-Status" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Teleservice-List" code="1486" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="TS-Code" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="TS-Code" code="1487" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Call-Barring-Info" code="1488" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="SS-Code" required="true" max="1"/>
                <rule avp="SS-Status" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="AMBR" code="1435" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Max-Requested-Bandwidth-UL" required="true" max="1"/>
                <rule avp="Max-Requested-Bandwidth-DL" required="true" max="1"/>
                <rule avp="Extended-Max-Requested-BW-UL" required="true" max="1"/>
                <rule avp="Extended-Max-Requested-BW-DL" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="APN-Configuration-Profile" code="1429" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Context-Identifier" required="true" max="1"/>
                <rule avp="Additional-Context-Identifier" required="true"/>
                <rule avp="Third-Context-Identifier" required="true"/>
                <rule avp="All-APN-Configurations-Included-Indicator" required="true" max="1"/>
                <rule avp="APN-Configuration" required="true"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Context-Identifier" code="1423" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Additional-Context-Identifier" code="1683" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Third-Context-Identifier" code="1719" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="All-APN-Configurations-Included-Indicator" code="1428" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="All_APN_CONFIGURATIONS_INCLUDED"/>
                <item code="1" name="MODIFIED|ADDED_APN_CONFIGURATIONS_INCLUDED"/>
            </data>
        </avp>

        <avp name="APN-Configuration" code="1430" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Context-Identifier" required="true" max="1"/>
                <rule avp="Served-Party-IP-Address" required="false" max="2"/>
                <rule avp="PDN-Type" required="true" max="1"/>
                <rule avp="Service-Selection" required="true" max="1"/>
                <rule avp="EPS-Subscribed-QoS-Profile" required="false" max="1"/>
                <rule avp="VPLMN-Dynamic-Address-Allowed" required="false" max="1"/>
                <rule avp="MIP6-Agent-Info" required="false" max="1"/>
                <rule avp="Visited-Network-Identifier" required="false" max="1"/>
                <rule avp="PDN-GW-Allocation-Type" required="false" max="1"/>
                <rule avp="TGPP-Charging-Characteristics" required="false" max="1"/>
                <rule avp="AMBR" required="false" max="1"/>
                <rule avp="Specific-APN-Info" required="false"/>
                <rule avp="APN-OI-Replacement" required="false" max="1"/>
                <rule avp="SIPTO-Permission" required="false" max="1"/>
                <rule avp="LIPA-Permission" required="false" max="1"/>
                <rule avp="Restoration-Priority" required="false" max="1"/>
                <rule avp="SIPTO-Local-Network-Permission" required="false" max="1"/>
                <rule avp="WLAN-offloadability" required="false" max="1"/>
                <rule avp="Non-IP-PDN-Type-Indicator" required="false" max="1"/>
                <rule avp="Non-IP-Data-Delivery-Mechanism" required="false" max="1"/>
		<rule avp="SCEF-ID" required="false"/>
		<rule avp="SCEF-Realm" required="false"/>
                <rule avp="Preferred-Data-Mode" required="false" max="1"/>
                <rule avp="PDN-Connection-Continuity" required="false" max="1"/>
                <rule avp="RDS-Indicator" required="false" max="1"/>
                <rule avp="Interworking-5GS-Indicator" required="false" max="1"/>
                <rule avp="Ethernet-PDN-Type-Indicator" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

	<avp name="Ethernet-PDN-Type-Indicator" code="1707" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="FALSE"/>
                <item code="1" name="TRUE"/>
            </data>
        </avp>

	<avp name="Interworking-5GS-Indicator" code="1706" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="NOT-SUBSCRIBED"/>
                <item code="1" name="SUBSCRIBED"/>
            </data>
        </avp>

        <avp name="Non-IP-Data-Delivery-Mechanism" code="1682" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="PDN-Connection-Continuity" code="1690" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Preferred-Data-Mode" code="1686" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Restoration-Priority" code="1663" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

	<avp name="RDS-Indicator" code="1697" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="DISABLED"/>
                <item code="1" name="ENABLED"/>
            </data>
        </avp>

        <avp name="SIPTO-Local-Network-Permission" code="1665" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

	<avp name="WLAN-offloadability" code="1667" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="WLAN-offloadability-EUTRAN" required="false"/>
                <rule avp="WLAN-offloadability-UTRAN" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="WLAN-offloadability-EUTRAN" code="1668" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="WLAN-offloadability-UTRAN" code="1669" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

	<avp name="Non-IP-PDN-Type-Indicator" code="1681" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="FALSE"/>
                <item code="1" name="TRUE"/>
            </data>
        </avp>

        <avp name="Served-Party-IP-Address" code="848" must="M,V" may="P" may-encrypt="N" vendor-id="10415">
            <data type="Address"/>
        </avp>

        <avp name="PDN-Type" code="1456" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="IPv4"/>
                <item code="1" name="IPv6"/>
                <item code="2" name="IPv4v6"/>
                <item code="3" name="IPv4_OR_IPv6"/>
            </data>
        </avp>

        <avp name="EPS-Subscribed-QoS-Profile" code="1431" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="QoS-Class-Identifier" required="true" max="1"/>
                <rule avp="Allocation-Retention-Priority" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="VPLMN-Dynamic-Address-Allowed" code="1432" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="NOTALLOWED"/>
                <item code="1" name="ALLOWED"/>
            </data>
        </avp>

        <avp name="PDN-GW-Allocation-Type" code="1438" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="STATIC"/>
                <item code="1" name="DYNAMIC"/>
            </data>
        </avp>

        <avp name="SIPTO-Permission" code="1613" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="SIPTO_ALLOWED"/>
                <item code="1" name="SIPTO_NOTALLOWED"/>
            </data>
        </avp>

        <avp name="LIPA-Permission" code="1618" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="LIPA-PROHIBITED"/>
                <item code="1" name="LIPA-ONLY"/>
                <item code="2" name="LIPA-CONDITIONAL"/>
            </data>
        </avp>

        <avp name="RAT-Frequency-Selection-Priority-ID" code="1440" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Trace-Data" code="1458" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Trace-Reference" required="true" max="1"/>
                <rule avp="Trace-Depth" required="true" max="1"/>
                <rule avp="Trace-NE-Type-List" required="true" max="1"/>
                <rule avp="Trace-Interface-List" required="false" max="1"/>
                <rule avp="Trace-Event-List" required="true" max="1"/>
                <rule avp="OMC-Id" required="false" max="1"/>
                <rule avp="Trace-Collection-Entity" required="true" max="1"/>
                <rule avp="MDT-Configuration" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Trace-Reference" code="1459" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Depth" code="1462" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="LIPA-PROHIBITED"/>
                <item code="1" name="LIPA-ONLY"/>
                <item code="2" name="LIPA-CONDITIONAL"/>
            </data>
        </avp>

        <avp name="Trace-NE-Type-List" code="1463" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Interface-List" code="1464" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Event-List" code="1465" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="OMC-Id" code="1466" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Event-List" code="1465" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Collection-Entity" code="1452" must="M,V" may="P" may-encrypt="N" vendor-id="10415">
            <data type="Address"/>
        </avp>

        <avp name="MDT-Configuration" code="1622" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Job-Type" required="true" max="1"/>
                <rule avp="Area-Scope" required="false"/>
                <rule avp="List-Of-Measurements" required="false"/>
                <rule avp="Reporting-Trigger" required="false"/>
                <rule avp="Report-Interval" required="false"/>
                <rule avp="Report-Amount" required="false"/>
                <rule avp="Event-Threshold-RSRP" required="false"/>
                <rule avp="Event-Threshold-RSRQ" required="false"/>
                <rule avp="Logging-Interval" required="false"/>
                <rule avp="Logging-Duration" required="false"/>
                <rule avp="Measurement-Period-LTE" required="false"/>
                <rule avp="Measurement-Period-UMTS" required="false"/>
                <rule avp="Collection-Period- RRM-LTE" required="false"/>
                <rule avp="Collection-Period-RRM-UMTS" required="false"/>
                <rule avp="Positioning-Method" required="false"/>
                <rule avp="Measurement-Quantity" required="false"/>
                <rule avp="Event-Threshold-Event-1F" required="false"/>
                <rule avp="Event-Threshold-Event-1I" required="false"/>
                <rule avp="MDT-Allowed-PLMN-Id" required="false"/>
                <rule avp="MBSFN-Area" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="MDT-Allowed-PLMN-Id" code="1671" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

	<avp name="Event-Threshold-Event-1F" code="1661" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

	<avp name="Event-Threshold-Event-1I" code="1662" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

        <avp name="Positioning-Method" code="1659" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Measurement-Quantity" code="1660" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

	<avp name="Measurement-Period-LTE" code="1655" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="1024 ms"/>
                <item code="2" name="2048 ms"/>
                <item code="4" name="5120 ms"/>
                <item code="5" name="10240 ms"/>
                <item code="6" name="1 min"/>
            </data>
        </avp>

	<avp name="Measurement-Period-UMTS" code="1656" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="1000 ms"/>
                <item code="1" name="2000 ms"/>
                <item code="2" name="3000 ms"/>
                <item code="3" name="4000 ms"/>
                <item code="4" name="6000 ms"/>
                <item code="5" name="8000 ms"/>
                <item code="6" name="12000 ms"/>
                <item code="7" name="16000 ms"/>
                <item code="8" name="20000 ms"/>
                <item code="9" name="24000 ms"/>
                <item code="10" name="28000 ms"/>
                <item code="11" name="32000 ms"/>
                <item code="12" name="64000 ms"/>
            </data>
        </avp>

	<avp name="Collection-Period-RRM-LTE" code="1657" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="100 ms"/>
                <item code="1" name="1000 ms"/>
                <item code="2" name="1024 ms"/>
                <item code="3" name="1280 ms"/>
                <item code="4" name="2048 ms"/>
                <item code="5" name="2560 ms"/>
                <item code="6" name="5120 ms"/>
                <item code="7" name="10000 ms"/>
                <item code="8" name="10240 ms"/>
                <item code="9" name="1 min"/>
            </data>
        </avp>

	<avp name="Collection-Period-RRM-UMTS" code="1658" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="100 ms"/>
                <item code="1" name="250 ms"/>
                <item code="2" name="500 ms"/>
                <item code="3" name="1000 ms"/>
                <item code="4" name="2000 ms"/>
                <item code="5" name="3000 ms"/>
                <item code="6" name="4000 ms"/>
                <item code="6" name="6000 ms"/>
            </data>
        </avp>

        <avp name="Event-Threshold-RSRP" code="1629" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Event-Threshold-RSRQ" code="1630" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

	<avp name="Logging-Interval" code="1631" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="1280"/>
                <item code="1" name="2560"/>
                <item code="2" name="5120"/>
                <item code="3" name="10240"/>
                <item code="4" name="20480"/>
                <item code="5" name="30720"/>
                <item code="6" name="40960"/>
                <item code="7" name="61440"/>
            </data>
        </avp>

	<avp name="Logging-Duration" code="1632" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="600"/>
                <item code="1" name="1200"/>
                <item code="2" name="2400"/>
                <item code="3" name="3600"/>
                <item code="4" name="5400"/>
                <item code="5" name="7200"/>
            </data>
        </avp>

	<avp name="MBSFN-Area" code="1694" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
		<rule avp="MBSFN-Area-ID" required="false"/>
		<rule avp="Carrier-Frequency" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="MBSFN-Area-ID" code="1695" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Carrier-Frequency" code="1696" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

	<avp name="Area-Scope" code="1624" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
		<rule avp="Cell-Global-Identity" required="false"/>
		<rule avp="E-UTRAN-Cell-Global-Identity" required="true"/>
		<rule avp="Routing-Area-Identity" required="false"/>
		<rule avp="Location-Area-Identity" required="false"/>
		<rule avp="Tracking-Area-Identity" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="List-Of-Measurements" code="1625" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Reporting-Trigger" code="1626" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

	<avp name="Job-Type" code="1623" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="Immediate-MDT-only"/>
                <item code="1" name="Logged-MDT-only"/>
                <item code="2" name="Trace-only"/>
                <item code="3" name="Immediate-MDT-and-Trace"/>
                <item code="4" name="RLF-reports-only"/>
                <item code="5" name="RCEF-reports-only"/>
                <item code="6" name="Logged-MBSFN-MDT"/>
            </data>
        </avp>

	<avp name="Report-Interval" code="1627" must="V" must-not="N" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="250"/>
                <item code="1" name="500"/>
                <item code="2" name="1000"/>
                <item code="3" name="2000"/>
                <item code="4" name="3000"/>
                <item code="5" name="4000"/>
                <item code="6" name="6000"/>
                <item code="7" name="8000"/>
                <item code="8" name="12000"/>
                <item code="9" name="16000"/>
                <item code="10" name="20000"/>
                <item code="11" name="24000"/>
                <item code="12" name="28000"/>
                <item code="13" name="32000"/>
                <item code="14" name="64000"/>
            </data>
        </avp>

	<avp name="Report-Amount" code="1628" must="V" must-not="N" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="1"/>
                <item code="1" name="2"/>
                <item code="2" name="4"/>
                <item code="3" name="8"/>
                <item code="4" name="16"/>
                <item code="5" name="32"/>
                <item code="6" name="64"/>
                <item code="7" name="infinity"/>
            </data>
        </avp>

        <avp name="GPRS-Subscription-Data" code="1467" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Complete-Data-List-Included-Indicator" required="true" max="1"/>
                <rule avp="PDP-Context" required="true" max="50"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Complete-Data-List-Included-Indicator" code="1468" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="All_PDP_CONTEXTS_INCLUDED"/>
                <item code="1" name="MODIFIED/ADDED_PDP CONTEXTS_INCLUDED"/>
            </data>
        </avp>

        <avp name="PDP-Context" code="1469" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Context-Identifier" required="true" max="1"/>
                <rule avp="PDP-Type" required="true" max="1"/>
                <rule avp="PDP-Address" required="false" max="1"/>
                <rule avp="QoS-Subscribed" required="true" max="1"/>
                <rule avp="VPLMN-Dynamic-Address-Allowed" required="false" max="1"/>
                <rule avp="Service-Selection" required="true" max="1"/>
                <rule avp="TGPP-Charging-Characteristics" required="false" max="1"/>
                <rule avp="Ext-PDP-Type" required="false" max="1"/>
                <rule avp="Ext-PDP-Address" required="false" max="1"/>
                <rule avp="AMBR" required="false" max="1"/>
                <rule avp="SIPTO-Permission" required="false" max="1"/>
                <rule avp="LIPA-Permission" required="false" max="1"/>
                <rule avp="Restoration-Priority" required="false" max="1"/>
                <rule avp="SIPTO-Local-Network-Permission" required="false" max="1"/>
                <rule avp="Non-IP-Data-Delivery-Mechanism" required="false" max="1"/>
		<rule avp="SCEF-ID" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="PDP-Type" code="1470" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="QoS-Subscribed" code="1404" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="VPLMN-Dynamic-Address-Allowed" code="1432" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="NOTALLOWED"/>
                <item code="1" name="ALLOWED"/>
            </data>
        </avp>

        <avp name="Ext-PDP-Type" code="1620" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Ext-PDP-Address" code="1621" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
            <data type="Address"/>
        </avp>

        <avp name="SIPTO-Permission" code="1613" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="SIPTO_ALLOWED"/>
                <item code="1" name="SIPTO_NOTALLOWED"/>
            </data>
        </avp>

        <avp name="CSG-Subscription-Data" code="1436" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="CSG-Id" required="true" max="1"/>
                <rule avp="Expiration-Date" required="false" max="1"/>
                <rule avp="Service-Selection" required="false"/>
		<rule avp="Visited-PLMN-Id" required="false"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Expiration-Date" code="1439" must="V,M" may-encrypt="N" vendor-id="10415">
            <data type="Time"/>
        </avp>

        <avp name="Roaming-Restricted-Due-To-Unsupported-Feature" code="1457" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="Roaming-Restricted-Due-To-Unsupported-Feature"/>
            </data>
        </avp>

        <avp name="Subscribed-Periodic-RAU-TAU-Timer" code="1619" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="MPS-Priority" code="1616" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="VPLMN-LIPA-Allowed" code="1617" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="LIPA-NOTALLOWED"/>
                <item code="1" name="LIPA-ALLOWED"/>
            </data>
        </avp>

        <avp name="Relay-Node-Indicator" code="1633" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="NOT_RELAY_NODE"/>
                <item code="1" name="RELAY_NODE"/>
            </data>
        </avp>

        <avp name="MDT-User-Consent" code="1634" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="CONSENT_NOT_GIVEN"/>
                <item code="1" name="CONSENT_GIVEN"/>
            </data>
        </avp>

        <avp name="Requested-EUTRAN-Authentication-Info" code="1408" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Grouped">
                <rule avp="Number-Of-Requested-Vectors" required="false" max="1"/>
                <rule avp="Immediate-Response-Preferred" required="false" max="1"/>
                <rule avp="Re-synchronization-Info" required="false" max="1"/>
            </data>
        </avp>

        <avp name="Number-Of-Requested-Vectors" code="1410" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Re-synchronization-Info" code="1411" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Immediate-Response-Preferred" code="1412" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Requested-UTRAN-GERAN-Authentication-Info" code="1409" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="Number-Of-Requested-Vectors" required="false" max="1"/>
                <rule avp="Immediate-Response-Preferred" required="false" max="1"/>
                <rule avp="Re-synchronization-Info" required="false" max="1"/>
            </data>
        </avp>

        <avp name="Visited-PLMN-Id" code="1407" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Error-Diagnostic" code="1614" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="GPRS_DATA_SUBSCRIBED"/>
                <item code="1" name="NO_GPRS_DATA_SUBSCRIBED"/>
                <item code="2" name="ODB-ALL-APN"/>
                <item code="3" name="ODB-HPLMN-APN"/>
                <item code="4" name="ODB-VPLMN-APN"/>
            </data>
        </avp>

        <avp name="Authentication-Info" code="1413" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="E-UTRAN-Vector" required="false"/>
                <rule avp="UTRAN-Vector" required="false"/>
                <rule avp="GERAN-Vector" required="false"/>
            </data>
        </avp>

        <avp name="E-UTRAN-Vector" code="1414" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="Item-Number" required="false" max="1"/>
                <rule avp="RAND" required="true" max="1"/>
                <rule avp="XRES" required="true" max="1"/>
                <rule avp="AUTN" required="true" max="1"/>
                <rule avp="KASME" required="true" max="1"/>
            </data>
        </avp>

        <avp name="UTRAN-Vector" code="1415" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="Item-Number" required="false"/>
                <rule avp="RAND" required="true"/>
                <rule avp="XRES" required="true"/>
                <rule avp="AUTN" required="true"/>
                <rule avp="Confidentiality-Key" required="true"/>
                <rule avp="Integrity-Key" required="true"/>
            </data>
        </avp>

        <avp name="GERAN-Vector" code="1416" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="Item-Number" required="false" max="1"/>
                <rule avp="RAND" required="true" max="1"/>
                <rule avp="SRES" required="true" max="1"/>
                <rule avp="Kc" required="true" max="1"/>
            </data>
        </avp>

        <avp name="Item-Number" code="1419" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="Cancellation-Type" code="1420" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="MME_UPDATE_PROCEDURE"/>
                <item code="1" name="SGSN_UDPATE_PROCEDURE"/>
                <item code="2" name="SUBSCRIPTION_WITHDRAWAL"/>
                <item code="3" name="UPDATE_PROCEDURE_IWF"/>
                <item code="4" name="INITIAL_ATTACH_PROCEDURE"/>
            </data>
        </avp>

        <avp name="RAND" code="1447" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="XRES" code="1448" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="AUTN" code="1449" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="KASME" code="1450" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Kc" code="1453" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="SRES" code="1454" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Confidentiality-Key" code="625" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="Integrity-Key" code="626" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="ULR-Flags" code="1405" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="AIR-Flags" code="1679" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="ULA-Flags" code="1406" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="CLR-Flags" code="1638" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="UE-SRVCC-Capability" code="1615" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="UE-SRVCC-NOT-SUPPORTED"/>
                <item code="1" name="UE-SRVCC-SUPPORTED"/>
            </data>
        </avp>

        <avp name="Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions" code="1493" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="NOT-SUPPORTED"/>
                <item code="1" name="SUPPORTED"/>
            </data>
        </avp>

        <avp name="Active-APN" code="1612" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="Context-Identifier" required="true" max="1"/>
                <rule avp="Service-Selection" required="false" max="1"/>
                <rule avp="MIP6-Agent-Info" required="false" max="1"/>
                <rule avp="Visited-Network-Identifier" required="false" max="1"/>
                <rule avp="Specific-APN-Info" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

	<avp name="IDA-Flags" code="1441" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="DSR-Flags" code="1421" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="DSA-Flags" code="1422" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Monitoring-Event-Report" code="3123" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="SCEF-Reference-ID" required="true"/>
		<rule avp="SCEF-Reference-ID-Ext" required="false"/>
		<rule avp="SCEF-ID" required="true"/>
		<rule avp="Reachability-Information" required="false"/>
		<rule avp="EPS-Location-Information" required="false" max="1"/>
		<rule avp="Monitoring-Type" required="false"/>
		<rule avp="Loss-Of-Connectivity-Reason" required="false"/>
		<rule avp="Idle-Status-Indication" required="false"/>
		<rule avp="Maximum-UE-Availability-Time" required="false" max="1"/>
		<rule avp="PDN-Connectivity-Status-Report" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Reachability-Information" code="3140" must="M" may="P" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Maximum-UE-Availability-Time" code="3329" must="M" may="P" vendor-id="10415">
	    <data type="Time"/>
	</avp>

	<avp name="Monitoring-Event-Config-Status" code="3142" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Service-Report" required="false"/>
		<rule avp="SCEF-Reference-ID" required="true"/>
		<rule avp="SCEF-ID" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Service-Report" code="3152" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Service-Result" required="false"/>
		<rule avp="Node-Type" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Node-Type" code="3153" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Service-Result" code="3146" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Vendor-Id" required="false"/>
		<rule avp="Service-Result-Code" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Service-Result-Code" code="3147" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Idle-Status-Indication" code="4322" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Idle-Status-Timestamp" required="true"/>
		<rule avp="Active-Time" required="true"/>
		<rule avp="Subscribed-Periodic-RAU-TAU-Timer" required="false" max="1"/>
		<rule avp="eDRX-Cycle-Length" required="false"/>
		<rule avp="DL-Buffering-Suggested-Packet-Count" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Loss-Of-Connectivity-Reason" code="3162" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Local-Time-Zone" code="1649" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Time-Zone" required="true"/>
		<rule avp="Daylight-Saving-Time" required="true"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Time-Zone" code="1642" must="V" must-not="M" may-encrypt="N"  vendor-id="10415">
	    <data type="UTF8String"/>
	</avp>

	<avp name="Daylight-Saving-Time" code="1650" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Enumerated">
		<item code="0" name="NO_ADJUSTMENT"/>
		<item code="1" name="PLUS_ONE_HOUR_ADJUSTMENT"/>
		<item code="2" name="PLUS_TWO_HOURS_ADJUSTMENT"/>
	    </data>
	</avp>

	<avp name="EPS-User-State" code="1495" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="MME-User-State" required="false"/>
		<rule avp="SGSN-User-State" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="MME-User-State" code="1497" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="User-State" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="SGSN-User-State" code="1498" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="User-State" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="User-State" code="1499" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Enumerated">
		<item code="0" name="DETACHED"/>
		<item code="1" name="ATTACHED_NOT_REACHABLE_FOR_PAGING"/>
		<item code="2" name="ATTACHED_REACHABLE_FOR_PAGING"/>
		<item code="3" name="CONNECTED_NOT_REACHABLE_FOR_PAGING"/>
		<item code="4" name="CONNECTED_REACHABLE_FOR_PAGING"/>
		<item code="5" name="RESERVED"/>
	    </data>
	</avp>

	<avp name="IMS-Voice-Over-PS-Sessions-Supported" code="1902" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Enumerated">
		<item code="0" name="NOT_SUPPORTED"/>
		<item code="1" name="SUPPORTED"/>
	    </data>
	</avp>

	<avp name="IDR-Flags" code="1490" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Reset-ID" code="1670" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Alert-Reason" code="1434" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Enumerated">
		<item code="0" name="UE_PRESENT"/>
		<item code="1" name="UE_MEMORY_AVAILABLE"/>
	    </data>
	</avp>

	<avp name="IAB-Operation-Permission" code="1709" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Enumerated">
		<item code="0" name="IAB_OPERATION_ALLOWED"/>
		<item code="1" name="IAB_OPERATION_NOTALLOWED"/>
	    </data>
	</avp>

	<avp name="EPS-Location-Information" code="1496" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="MME-Location-Information" required="true"/>
		<rule avp="SGSN-Location-Information" required="true"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

        <avp name="SGSN-Location-Information" code="1601" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Cell-Global-Identity" required="false"/>
		<rule avp="Location-Area-Identity" required="false"/>
		<rule avp="Service-Area-Identity" required="false"/>
		<rule avp="Routing-Area-Identity" required="false"/>
		<rule avp="Geographical-Information" required="false"/>
		<rule avp="Geodetic-Information" required="false"/>
		<rule avp="Current-Location-Retrieved" required="false"/>
		<rule avp="Age-Of-Location-Information" required="false"/>
		<rule avp="User-CSG-Information" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Location-Global-Identity" code="1606" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Service-Global-Identity" code="1607" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Routing-Global-Identity" code="1605" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Cell-Global-Identity" code="1604" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="MME-Location-Information" code="1600" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="E-UTRAN-Cell-Global-Identity" required="true"/>
		<rule avp="Tracking-Area-Identity" required="false"/>
		<rule avp="Geographical-Information" required="false"/>
		<rule avp="Geodetic-Information" required="false"/>
		<rule avp="Current-Location-Retrieved" required="false"/>
		<rule avp="Age-Of-Location-Information" required="false"/>
		<rule avp="User-CSG-Information" required="false"/>
		<rule avp="eNodeB-ID" required="false"/>
		<rule avp="Extended-eNodeB-ID" required="false"/>
		<rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="eNodeB-ID" code="4008" must="M,V" may="P"  may-encrypt="Y" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Extended-eNodeB-ID" code="4013" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Age-Of-Location-Information" code="1611" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned64"/>
	</avp>

	<avp name="E-UTRAN-Cell-Global-Identity" code="1602" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Tracking-Area-Identity" code="1603" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Routing-Area-Identity" code="1605" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
    </avp>

	<avp name="Location-Area-Identity" code="1606" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
    </avp>

	<avp name="Geographical-Information" code="1608" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Geodetic-Information" code="1609" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Current-Location-Retrieved" code="1610" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Enumerated">
		<item code="0" name="ACTIVE-LOCATION-RETRIEVAL"/>
	    </data>
	</avp>

	<avp name="TGPP-Charging-Characteristics" code="13" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
	    <data type="UTF8String"/>
	</avp>

	<avp name="Equivalent-PLMN-List" code="1637" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Visited-PLMN-Id" required="true"/>
	    </data>
	</avp>

	<avp name="MME-Number-for-MT-SMS" code="1645" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="SMS-Register-Request" code="1648" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Enumerated">
		<item code="0" name="SMS_REGISTRATION_REQUIRED"/>
		<item code="1" name="SMS_REGISTRATION_NOT_PREFERRED"/>
	    </data>
	</avp>

	<avp name="SGs-MME-Identity" code="1664" must="V" must-not="M" may-encrypt="N"  vendor-id="10415">
	    <data type="UTF8String"/>
	</avp>

	<avp name="Coupled-Node-Diameter-ID" code="1666" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="DiameterIdentity"/>
	</avp>

	<avp name="Adjacent-PLMNs" code="1672" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Visited-PLMN-Id" required="true"/>
	    </data>
	</avp>

	<avp name="Supported-Services" code="3143" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Supported-Monitoring-Events" required="false"/>
	    </data>
	</avp>

	<avp name="Supported-Monitoring-Events" code="3144" must="M,V" may-encrypt="N" vendor-id="10415" >
	    <data type="Unsigned64"/>
	</avp>

	<avp name="A-MSISDN" code="1643" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="ProSe-Subscription-Data" code="3701" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="ProSe-Permission" required="true"/>
	    </data>
	</avp>

	<avp name="ProSe-Permission" code="3702" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Emergency-Services" code="1538" must="V" must-not="M,P" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Broadcast-Location-Assistance-Data-Types" code="1700" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned64"/>
	</avp>

	<avp name="Aerial-UE-Subscription-Information" code="1699" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="eDRX-Related-RAT" code="1705" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
	        <rule avp="RAT-Type" required="false" mmax="1"/>
	        <rule avp="AVP" required="false"/>
	    </data>
	</avp>

	<avp name="Core-Network-Restrictions" code="1704" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Maximum-UE-AvailabilityTime" code="3329" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Time"/>
	</avp>

	<avp name="Last-UE-Activity-Time" code="1494" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Time"/>
	</avp>

        <avp name="Active-Time" code="4324" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Service-Gap-Time" code="1698" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Subscription-Data-Flags" code="1654" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Adjacent-Access-Restriction-Data" code="1673" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Visited-PLMN-Id" required="true"/>
		<rule avp="Access-Restriction-Data" required="true"/>
	    </data>
	</avp>

	<avp name="DL-Buffering-Suggested-Packet-Count" code="1674" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

	<avp name="IMSI-Group-Id" code="1675" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Group-Service-Id" required="true"/>
		<rule avp="Group-PLMN-Id" required="true"/>
		<rule avp="Local-Group-Id" required="true"/>
	    </data>
	</avp>

	<avp name="Group-Service-Id" code="1676" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Group-PLMN-Id" code="1677" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Local-Group-Id" code="1678" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="UE-Usage-Type" code="1680" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="AESE-Communication-Pattern" code="3113" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="SCEF-Reference-ID" required="false"/>
		<rule avp="SCEF-Reference-ID-Ext" required="false"/>
		<rule avp="SCEF-ID" required="true"/>
		<rule avp="SCEF-Reference-ID-for-Deletion" required="false"/>
		<rule avp="SCEF-Reference-ID-for-Deletion-Ext" required="false"/>
		<rule avp="Communication-Pattern-Set" required="false"/>
		<rule avp="MTC-Provider-Info" required="false"/>
	    </data>
	</avp>

	<avp name="SCEF-Reference-ID" code="3124" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>
	<avp name="SCEF-Reference-ID-for-Deletion" code="3126" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="SCEF-Reference-ID-Ext" code="3186" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned64"/>
	</avp>

	<avp name="SCEF-Reference-ID-for-Deletion-Ext" code="3187" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned64"/>
	</avp>

	<avp name="SCEF-ID" code="3125" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="DiameterIdentity"/>
	</avp>

	<avp name="Communication-Pattern-Set" code="3114" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Periodic-Communication-Indicator" required="false"/>
		<rule avp="Communication-Duration-Time" required="false"/>
		<rule avp="Periodic-Time" required="false"/>
		<rule avp="Scheduled-Communication-Time" required="false"/>
		<rule avp="Stationary-Indication" required="false"/>
		<rule avp="Reference-ID-Validity-Time" required="false"/>
		<rule avp="Traffic-Profile" required="false"/>
		<rule avp="Battery-Indicator" required="false"/>
	    </data>
	</avp>

	<avp name="MTC-Provider-Info" code="3178" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="MTC-Provider-ID" required="false"/>
	    </data>
	</avp>

	<avp name="MTC-Provider-ID" code="3179" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="UTF8String"/>
	</avp>

	<avp name="Periodic-Communication-Indicator" code="3115" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Communication-Duration-Time" code="3116" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Periodic-Time" code="3117" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Stationary-Indication" code="3119" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Reference-ID-Validity-Time" code="3148" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Time"/>
	</avp>

	<avp name="Traffic-Profile" code="3183" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Battery-Indicator" code="3185" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Scheduled-Communication-Time" code="3118" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Day-Of-Week-Mask" required="false"/>
		<rule avp="Time-Of-Day-Start" required="false"/>
		<rule avp="Time-Of-Day-End" required="false"/>
	    </data>
	</avp>

	<avp name="Day-Of-Week-Mask" code="563" vendor-id="10415" may="P" must-not="M">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Time-Of-Day-Start" code="561" vendor-id="10415" may="P" must-not="M">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Time-Of-Day-End" code="562" vendor-id="10415" may="P" must-not="M">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Monitoring-Event-Configuration" code="3122" must="M" may="P" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="SCEF-Reference-ID" required="false"/>
		<rule avp="SCEF-Reference-ID-Ext" required="false"/>
		<rule avp="SCEF-ID" required="true"/>
		<rule avp="Monitoring-Type" required="true"/>
		<rule avp="SCEF-Reference-ID-for-Deletion" required="false"/>
		<rule avp="SCEF-Reference-ID-for-Deletion-Ext" required="false"/>
		<rule avp="Maximum-Number-of-Reports" required="false"/>
		<rule avp="Monitoring-Duration" required="false"/>
		<rule avp="Charged-Party" required="false"/>
		<rule avp="UE-Reachability-Configuration" required="false"/>
		<rule avp="Location-Information-Configuration" required="false"/>
		<rule avp="SCEF-Realm" required="false"/>
		<rule avp="External-Identifier" required="false"/>
		<rule avp="MTC-Provider-Info" required="false"/>
		<rule avp="PDN-Connectivity-Status-Configuration" required="false"/>
	    </data>
	</avp>

        <avp name="PDN-Connectivity-Status-Configuration" code="3180" vendor-id="10415" must="V" must-not="M" may-encrypt="N">
	    <data type="Grouped">
		<rule avp="Service-Selection" required="true" max="1"/>
	    </data>
	</avp>

	<avp name="External-Identifier" code="3111" must="V,M" may-encrypt="N" vendor-id="10415">
	    <data type="UTF8String"/>
	</avp>

	<avp name="SCEF-Realm" code="1684" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="DiameterIdentity"/>
	</avp>

	<avp name="Monitoring-Type" code="3127" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Maximum-Number-of-Reports" code="3128" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Monitoring-Duration" code="3148" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Time"/>
	</avp>

	<avp name="Charged-Party" code="857" must="V,M" may="-" vendor-id="10415">
	    <data type="UTF8String"/>
	</avp>

	<avp name="UE-Reachability-Configuration" code="3129" vendor-id="10415" must="M,V" may-encrypt="N">
	    <data type="Grouped">
		<rule avp="Reachability-Type" required="true"/>
		<rule avp="Maximum-Response-Time" required="true"/>
	    </data>
	</avp>

	<avp name="Reachability-Type" code="3132" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Maximum-Response-Time" code="3134" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Location-Information-Configuration" code="3135" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="MONTE-Location-Type" required="true"/>
		<rule avp="Accuracy" required="true"/>
		<rule avp="Periodic-Time" required="false"/>
	    </data>
	</avp>

	<avp name="MONTE-Location-Type" code="3136" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Accuracy" code="3137" must="M,V" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Emergency-Info" code="1687" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="MIP6-Agent-Info" required="false"/>
	    </data>
	</avp>

	<avp name="V2X-Subscription-Data" code="1688" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="V2X-Permission" required="false"/>
	  	<rule avp="UE-PC5-AMBR" required="false"/>
	    </data>
	</avp>

	<avp name="V2X-Permission" code="1689" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="UE-PC5-AMBR" code="1693" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="V2X-Subscription-Data-Nr" code="1710" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="V2X-Permission" required="false"/>
		<rule avp="UE-PC5-AMBR" required="false"/>
		<rule avp="UE-PC5-QoS" required="false"/>
	    </data>
	</avp>

	<avp name="UE-PC5-QoS" code="1711" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
	 	<rule avp="PC5-QoS-Flow" required="true"/>
		<rule avp="PC5-Link-AMBR" required="false"/>
	    </data>
	</avp>

	<avp name="PC5-Link-AMBR" code="1718" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

	<avp name="PC5-QoS-Flow" code="1712" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="FiveQI" required="true"/>
		<rule avp="PC5-Flow-Bitrates" required="false"/>
		<rule avp="PC5-Range" required="false"/>
	    </data>
	</avp>

	<avp name="FiveQI" code="1713" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

	<avp name="PC5-Range" code="1717" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

	<avp name="PC5-Flow-Bitrates" code="1714" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Guaranteed-Flow-Bitrates" required="false"/>
		<rule avp="Maximum-Flow-Bitrates" required="false"/>
	    </data>
	</avp>

	<avp name="Guaranteed-Flow-Bitrates" code="1715" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

	<avp name="Maximum-Flow-Bitrates" code="1716" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Integer32"/>
	</avp>

	<avp name="eDRX-Cycle-Length" code="1691" vendor-id="10415" must="V" must-not="M" may-encrypt="N">
	    <data type="Grouped">
		<rule avp="RAT-Type" required="true" max="1"/>
		<rule avp="eDRX-Cycle-Length-Value" required="true"/>
	    </data>
	</avp>

	<avp name="eDRX-Cycle-Length-Value" code="1692" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

	<avp name="Paging-Time-Window" code="1701" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Grouped">
		<rule avp="Operation-Mode" required="true"/>
		<rule avp="Paging-Time-Window-Length" required="true"/>
	    </data>
	</avp>

	<avp name="Subscribed-ARPI" code="1708" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Operation-Mode" code="1702" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="Unsigned32"/>
	</avp>

	<avp name="Paging-Time-Window-Length" code="1703" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
	    <data type="OctetString"/>
	</avp>

        <avp name="Specific-APN-Info" code="1472" vendor-id="10415" must="M,V" may-encrypt="N">
            <data type="Grouped">
                <rule avp="Service-Selection" required="true" max="1"/>
                <rule avp="MIP6-Agent-Info" required="true" max="1"/>
                <rule avp="Visited-Network-Identifier" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Context-Identifier" code="1423" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32"/>
        </avp>

        <avp name="PUR-Flags" code="1635" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32" />
        </avp>

        <avp name="PUA-Flags" code="1442" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32" />
        </avp>

        <avp name="NOR-Flags" code="1443" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="Unsigned32" />
        </avp>

        <avp name="Subscribed-VSRVCC" code="1636" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="Enumerated">
                <item code="0" name="VSRVCC_SUBSCRIBED" />
            </data>
        </avp>

        <avp name="Visited-Network-Identifier" code="600" must="M,V" may-encrypt="N" vendor-id="10415">
            <data type="OctetString"/>
        </avp>

        <avp name="User-Id" code="1444" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <data type="UTF8String"/>
        </avp>
        <avp name="Service-Selection" code="493" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="0">
            <data type="UTF8String"/>
        </avp>
         <avp name="MIP6-Agent-Info" code="486" must="M" may="P" must-not="V" may-encrypt="-">
                <data type="Grouped">
                    <rule avp="MIP-Home-Agent-Address" required="false" max="2"/>
                    <rule avp="MIP-Home-Agent-Host" required="false" max="1"/>
                    <rule avp="MIP6-Home-Link-Prefix" required="false" max="1"/>
                    <rule avp="AVP" required="false"/>
                </data>
            </avp>

            <avp name="MIP6-Home-Link-Prefix" code="125">
                <data type="OctetString"/>
            </avp>

            <avp name="MIP-Home-Agent-Address" code="334" must="M" must-not="V">
                <data type="Address"/>
            </avp>

            <!-- RFC 4004 -->
            <avp name="MIP-Home-Agent-Host" code="348" must="M" may="P" must-not="V" may-encrypt="Y">
                <data type="Grouped">
                    <rule avp="Destination-Realm" required="true" max="1"/>
                    <rule avp="Destination-Host" required="true" max="1"/>
                    <rule avp="AVP" required="false"/>
                </data>
            </avp>


    </application>
</diameter>`

var tgpps6cXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
    <application id="16777312" type="auth" name="TGPP S6C">
        <vendor id="10415" name="TGPP"/>
<command code="8388647" short="SR" name="Send-Routing-Info-for-SM" >
                         <request>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="false" max="1" pointer="true" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="false" max="1" pointer="true" />
    <rule avp="Destination-Realm" required="true" max="1" />
    <rule avp="MSISDN" required="false" max="1" pointer="true" />
    <rule avp="User-Name" required="false" max="1" pointer="true" />
    <rule avp="SMSMI-Correlation-ID" required="false" max="1" pointer="true"/>
    <rule avp="Supported-Features" required="false" />
    <rule avp="SC-Address" required="false" max="1" pointer="true" />
    <rule avp="SM-RP-MTI" required="false" max="1" pointer="true" />
    <rule avp="SM-RP-SMEA" required="false" max="1" pointer="true" />
    <rule avp="SRR-Flags" required="false" max="1" pointer="true" />
    <rule avp="SM-Delivery-Not-Intended" required="false" max="1" pointer="true" />
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
                         </request>

                         <answer>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1"  pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="false" max="1"pointer="true" />
    <rule avp="Result-Code" required="false" max="1" pointer="true"/>
    <rule avp="Experimental-Result" required="false" max="1" pointer="true" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="User-Name" required="false" max="1" pointer="true" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="Serving-Node" required="false" max="1" pointer="true" />
    <rule avp="Additional-Serving-Node" required="false" max="1" pointer="true" />
    <rule avp="SMSF-3GPP-Address" required="false" max="1" pointer="true" />
    <rule avp="SMSF-Non-3GPP-Address" required="false" max="1" pointer="true" />
    <rule avp="LMSI" required="false" max="1" pointer="true" />
    <rule avp="User-Identifier" required="false" max="1" pointer="true" />
    <rule avp="MWD-Status" required="false" max="1" pointer="true" />
    <rule avp="MME-Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    <rule avp="MSC-Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    <rule avp="SGSN-Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    <rule avp="SMSF-3GPP-Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    <rule avp="SMSF-Non-3GPP-Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    <rule avp="AVP" required="false" />
    <rule avp="Failed-AVP" required="false" max="1" pointer="true" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
                         </answer>
</command>

<command code="8388648" short="AL" name="Alert-Service-Centre" >
<request>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="false" max="1" pointer="true" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="false" max="1" pointer="true" />
    <rule avp="Destination-Realm" required="true" max="1" />
    <rule avp="SC-Address" required="true" max="1" pointer="true" />
    <rule avp="User-Identifier" required="true" max="1" pointer="true" />
    <rule avp="SMSMI-Correlation-ID" required="false" max="1" pointer="true"/>
    <rule avp="Maximum-UE-Availability-Time" required="false" max="1" pointer="true" />
    <rule avp="SMS-GMSC-Alert-Event" required="false" max="1" pointer="true" />
    <rule avp="Serving-Node" required="false" max="1" pointer="true" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</request>
<answer>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1"  pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="false" max="1" pointer="true" />
    <rule avp="Result-Code" required="false" max="1" pointer="true"/>
    <rule avp="Experimental-Result" required="false" max="1" pointer="true" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="AVP" required="false" />
    <rule avp="Failed-AVP" required="false" max="1" pointer="true" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</answer>
</command>

<command code="8388649" short="RD" name="Report-SM-Delivery-Status" >
    <request>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="false" max="1" pointer="true" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="false" max="1" pointer="true" />
    <rule avp="Destination-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="User-Identifier" required="true" max="1" />
    <rule avp="SMSMI-Correlation-ID" required="false" max="1" pointer="true"/>
    <rule avp="SC-Address" required="true" max="1" />
    <rule avp="SM-Delivery-Outcome" required="true" max="1" />
    <rule avp="RDR-Flags" required="false" max="1" pointer="true" />
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
    </request>
<answer>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1"  pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="false" max="1" pointer="true" />
    <rule avp="Result-Code" required="false" max="1" pointer="true"/>
    <rule avp="Experimental-Result" required="false" max="1" pointer="true" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="User-Identifier" required="false" max="1" pointer="true" />
    <rule avp="AVP" required="false" />
    <rule avp="Failed-AVP" required="false" max="1" pointer="true" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</answer>
</command>

<avp name="Session-Id" code="263" must="M" may="P" must-not="V" may-encrypt="Y">
    <data type="UTF8String"/>
</avp>

<avp name="DRMP" code="301" must-not="V">
    <data type="Enumerated">
        <item code="0" name="PRIORITY_0"/>
        <item code="1" name="PRIORITY_1"/>
        <item code="2" name="PRIORITY_2"/>
        <item code="3" name="PRIORITY_3"/>
        <item code="4" name="PRIORITY_4"/>
        <item code="5" name="PRIORITY_5"/>
        <item code="6" name="PRIORITY_6"/>
        <item code="7" name="PRIORITY_7"/>
        <item code="8" name="PRIORITY_8"/>
        <item code="9" name="PRIORITY_9"/>
        <item code="10" name="PRIORITY_10"/>
        <item code="11" name="PRIORITY_11"/>
        <item code="12" name="PRIORITY_12"/>
        <item code="13" name="PRIORITY_13"/>
        <item code="14" name="PRIORITY_14"/>
        <item code="15" name="PRIORITY_15"/>
    </data>
</avp>

<avp name="Vendor-Specific-Application-Id" code="260" must="M" may="P" must-not="V" may-encrypt="N" vendor-id="10415">
    <data type="Grouped" >
        <rule avp="Vendor-ID" required="false" max="1" />
        <rule avp="Auth-Application-Id" required="false" max="1" />
        <rule avp="Acct-Application-Id" required="false" max="1" />
    </data>
</avp>

<avp name="Auth-Session-State" code="277" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Enumerated">
        <item code="0" name="STATE_MAINTAINED"/>
        <item code="1" name="NO_STATE_MAINTAINED"/>
    </data>
</avp>

<avp name="Origin-Host" code="264" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="Origin-Realm" code="296" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="Destination-Host" code="293" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="Destination-Realm" code="283" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="MSISDN" code="701" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="OctetString" />
</avp>

<avp name="User-Name" code="1" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="10415">
    <data type="UTF8String" />
</avp>

<avp name="SMSMI-Correlation-ID" code="3324" must="V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="Grouped" >
        <rule avp="HSS-ID" required="false" max="1" pointer="true" />
        <rule avp="Originating-SIP-URI" required="false" max="1" pointer="true" />
        <rule avp="Destination-SIP-URI" required="false" max="1" pointer="true" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="HSS-ID" code="3325" must="V" may="-" must-not="-" may-encrypt="N">
    <data type="UTF8String" />
</avp>

<avp name="Originating-SIP-URI" code="3325" must="V" may="-" must-not="-" may-encrypt="N">
    <data type="UTF8String" />
</avp>

<avp name="Destination-SIP-URI" code="3327" must="V" may="-" must-not="-" may-encrypt="N">
    <data type="UTF8String" />
</avp>

<avp name="Supported-Features" code="628" must="V" may-encrypt="N" vendor-id="10415">
    <data type="Grouped" >
        <rule avp="Vendor-ID" required="true" max="1" />
        <rule avp="Feature-List-ID" required="true" max="1" />
        <rule avp="Feature-List" required="true" max="1" />
    </data>
</avp>

<avp name="Vendor-ID" code="266" must="M" may-encrypt="-" vendor-id="10415">
    <data type="Unsigned32" />
</avp>

<avp name="Feature-List-ID" code="629" must="V" may-encrypt="N" vendor-id="10415">
    <data type="Unsigned32" />
</avp>

<avp name="Feature-List" code="630" must="V" may-encrypt="N" vendor-id="10415">
    <data type="Unsigned32" />
</avp>

<avp name="SC-Address" code="3300" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="OctetString" />
</avp>

<avp name="SM-RP-MTI" code="3308" must="M,V" may="-" must-not="-" may-encrypt="N" >
    <data type="Enumerated" >
        <item code="0" name="SM_DELIVER"  />
        <item code="1" name="SM_STATUS_REPORT"  />
    </data>
</avp>

<avp name="SM-RP-SMEA" code="3309" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="OctetString" />
</avp>

<avp name="SRR-Flags" code="3310" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="Unsigned32" />
</avp>

<avp name="SM-Delivery-Not-Intended" code="3311" must="M,V" may="-" must-not="-" may-encrypt="N" >
    <data type="Enumerated" >
        <item code="0" name="ONLY_IMSI_REQUESTED"  />
        <item code="1" name="ONLY_MCC_MNC_REQUESTED"  />
    </data>
</avp>

<avp name="Proxy-Info" code="284" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="Proxy-Host" required="true" max="1" />
        <rule avp="Proxy-State" required="true" max="1" />
    </data>
</avp>

<avp name="Proxy-Host" code="280" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="DiameterIdentity" />
</avp>

<avp name="Proxy-State" code="33" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="OctetString" />
</avp>

<avp name="Route-Record" code="282" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="DiameterIdentity" />
</avp>

<avp name="Result-Code" code="268" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Unsigned32" />
</avp>

<avp name="Experimental-Result" code="297" must="M" may="P" must-not="V" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="Vendor-ID" required="true" max="1"/>
        <rule avp="Experimental-Result-Code" required="true" max="1"/>
    </data>
</avp>

<avp name="Experimental-Result-Code" code="298" must="M" may="P" must-not="V" may-encrypt="N">
      <data type="Unsigned32"  />
</avp>

<avp name="Serving-Node" code="2401" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SGSN-Name" required="false" max="1" pointer="true" />
        <rule avp="SGSN-Realm" required="false" max="1" pointer="true" />
        <rule avp="SGSN-Number" required="false" max="1" pointer="true" />
        <rule avp="MME-Name" required="false" max="1" pointer="true" />
        <rule avp="MME-Realm" required="false" max="1" pointer="true" />
        <rule avp="MME-Number-for-MT-SMS" required="false" max="1" pointer="true" />
        <rule avp="MSC-Number" required="false" max="1" pointer="true" />
        <rule avp="IP-SM-GW-Number" required="false" max="1" pointer="true" />
        <rule avp="IP-SM-GW-Name" required="false" max="1" pointer="true" />
        <rule avp="IP-SM-GW-Realm" required="false" max="1" pointer="true" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="SGSN-Name" code="2409" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="SGSN-Realm" code="2410" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="SGSN-Number" code="1489" must="M,V" may="-" must-not="P,V" may-encrypt="N">
    <data type="OctetString" />
</avp>
<avp name="IP-SM-GW-Number" code="3100" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="OctetString"/>
</avp>
<avp name="IP-SM-GW-Name" code="3101" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>
<avp name="IP-SM-GW-Realm" code="3112" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="MME-Name" code="2410" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="MME-Realm" code="2408" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="MME-Number-for-MT-SMS" code="1645" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="OctetString" />
</avp>

<avp name="MSC-Number" code="2403" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="OctetString" />
</avp>

<avp name="Additional-Serving-Node" code="2406" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SGSN-Name" required="false" max="1" pointer="true" />
        <rule avp="SGSN-Realm" required="false" max="1" pointer="true" />
        <rule avp="SGSN-Number" required="false" max="1" pointer="true" />
        <rule avp="MME-Name" required="false" max="1" pointer="true" />
        <rule avp="MME-Realm" required="false" max="1" pointer="true" />
        <rule avp="MME-Number-for-MT-SMS" required="false" max="1" pointer="true" />
        <rule avp="MSC-Number" required="false" max="1" pointer="true" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="SMSF-3GPP-Address" code="3344" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SMSF-3GPP-Number" required="false" max="1" pointer="true" />
        <rule avp="SMSF-3GPP-Name" required="false" max="1" pointer="true" />
        <rule avp="SMSF-3GPP-Realm" required="false" max="1" pointer="true" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="SMSF-3GPP-Number" code="3338" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="OctetString" />
</avp>

<avp name="SMSF-3GPP-Name" code="3340" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="SMSF-3GPP-Realm" code="3342" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="SMSF-Non-3GPP-Address" code="3345" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SMSF-Non-3GPP-Number" required="false" max="1" pointer="true" />
        <rule avp="SMSF-Non-3GPP-Name" required="false" max="1" pointer="true" />
        <rule avp="SMSF-Non-3GPP-Realm" required="false" max="1" pointer="true" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="SMSF-Non-3GPP-Number" code="3339" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="OctetString" />
</avp>

<avp name="SMSF-Non-3GPP-Name" code="3341" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="SMSF-Non-3GPP-Realm" code="3343" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="User-Identifier" code="3102" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="User-Name" required="false" max="1" pointer="true" />
        <rule avp="MSISDN" required="false" max="1" pointer="true" />
        <rule avp="External-Identifier" required="false" max="1" pointer="true" />
        <rule avp="LMSI" required="false" max="1" pointer="true" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="External-Identifier" code="3111" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="UTF8String" />
</avp>

<avp name="LMSI" code="2400" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="OctetString" />
</avp>

<avp name="Maximum-UE-Availability-Time" code="3329" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Time"/>
</avp>

<avp name="SMS-GMSC-Alert-Event" code="3333" must="-" may="-" must-not="V" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="SM-Delivery-Outcome" code="3316" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="MME-SM-Delivery-Outcome" required="false" max="1" pointer="true" />
        <rule avp="MSC-SM-Delivery-Outcome" required="false" max="1" pointer="true" />
        <rule avp="SGSN-SM-Delivery-Outcome" required="false" max="1" pointer="true" />
        <rule avp="IP-SM-GW-SM-Delivery-Outcome" required="false" max="1" pointer="true" />
        <rule avp="SMSF-3GPP-SM-Delivery-Outcome" required="false" max="1" pointer="true" />
        <rule avp="SMSF-Non-3GPP-SM-Delivery-Outcome" required="false" max="1" pointer="true" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="MME-SM-Delivery-Outcome" code="3317" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SM-Delivery-Cause" required="false" max="1" pointer="true" />
        <rule avp="Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    </data>
</avp>

<avp name="MSC-SM-Delivery-Outcome" code="3318" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SM-Delivery-Cause" required="false" max="1" pointer="true" />
        <rule avp="Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    </data>
</avp>

<avp name="SGSN-SM-Delivery-Outcome" code="3319" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SM-Delivery-Cause" required="false" max="1" pointer="true" />
        <rule avp="Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    </data>
</avp>

<avp name="IP-SM-GW-SM-Delivery-Outcome" code="3320" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SM-Delivery-Cause" required="false" max="1" pointer="true" />
        <rule avp="Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    </data>
</avp>

<avp name="SMSF-3GPP-SM-Delivery-Outcome" code="3336" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SM-Delivery-Cause" required="false" max="1" pointer="true" />
        <rule avp="Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    </data>
</avp>

<avp name="SMSF-Non-3GPP-SM-Delivery-Outcome" code="3337" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Grouped" >
        <rule avp="SM-Delivery-Cause" required="false" max="1" pointer="true" />
        <rule avp="Absent-User-Diagnostic-SM" required="false" max="1" pointer="true" />
    </data>
</avp>

<avp name="SM-Delivery-Cause" code="3321" must="M,V" may="-" must-not="-" may-encrypt="N" >
    <data type="Enumerated" >
        <item code="0" name="UE_ MEMORY_CAPACITY_EXCEEDED"  />
        <item code="1" name="ABSENT_USER"  />
        <item code="2" name="SUCCESSFUL_TRANSFER"  />
    </data>
</avp>

<avp name="Absent-User-Diagnostic-SM" code="3322" must="M,V" may="-" must-not="V" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="RDR-Flags" code="3323" must="V" may="-" must-not="-" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="Failed-AVP" code="279" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Grouped" />
</avp>

<avp name="MWD-Status" code="3312" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="MME-Absent-User-Diagnostic-SM" code="3313" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="MSC-Absent-User-Diagnostic-SM" code="3314" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="SGSN-Absent-User-Diagnostic-SM" code="3315" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="SMSF-3GPP-Absent-User-Diagnostic-SM" code="3334" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="SMSF-Non-3GPP-Absent-User-Diagnostic-SM" code="3335" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Unsigned32"/>
</avp>

<avp name="IP-SM-GW-Number" code="3100" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="OctetString"/>
</avp>

<avp name="IP-SM-GW-Name" code="3101" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

<avp name="IP-SM-GW-Realm" code="3112" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="DiameterIdentity"/>
</avp>

        </application>
</diameter>`

var tgppshXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
    <application id="16777217" type="auth" name="TGPP SH">
        <vendor id="10415" name="TGPP"/>
<command code="306" short="UD" name="User-Data" >
			<request>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="false" max="1" pointer="true" />
    <rule avp="Destination-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="User-Identity" required="true" max="1" />
    <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true"/>
    <rule avp="Wildcarded-IMPU" required="false" max="1" pointer="true" />
    <rule avp="Server-Name" required="false" max="1" pointer="true" />
    <rule avp="Service-Indication" required="false" />
    <rule avp="Data-Reference" required="true"  />
    <rule avp="Identity-Set" required="false" />
    <rule avp="Requested-Domain" required="false" max="1" pointer="true" />
    <rule avp="Current-Location" required="false" max="1" pointer="true" />
    <rule avp="DSAI-Tag" required="false" />
    <rule avp="Session-Priority" required="false" max="1" pointer="true" />
    <rule avp="User-Name" required="false" max="1" pointer="true" />
    <rule avp="Requested-Nodes" required="false" max="1" pointer="true" />
    <rule avp="Serving-Node-Indication" required="false" max="1" pointer="true" />
    <rule avp="Pre-paging-Supported" required="false" max="1" pointer="true" />
    <rule avp="Local-Time-Zone-Indication" required="false" max="1" pointer="true" />
    <rule avp="UDR-Flags" required="false" max="1" pointer="true" />
    <rule avp="Call-Reference-Info" required="false" max="1" pointer="true" />
    <rule avp="OC-Supported-Features" required="false" max="1" pointer="true" />
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
                         </request>

                         <answer>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1"  pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1" />
    <rule avp="Result-Code" required="false" max="1" pointer="true"/>
    <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="Wildcarded-Public-Identity" required="false" max="1"  pointer="true"/>
    <rule avp="Wildcarded-IMPU" required="false" max="1" pointer="true" />
    <rule avp="User-Data" required="false" max="1" pointer="true" />
    <rule avp="OC-Supported-Features" required="false" max="1" pointer="true"/>
    <rule avp="OC-OLR" required="false" max="1" pointer="true"/>
    <rule avp="Load" required="false" />
    <rule avp="AVP" required="false" />
    <rule avp="Failed-AVP" required="false" max="1" pointer="true" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
                         </answer>
</command>

<command code="307" short="PU" name="Profile-Update">
<request>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="false" max="1" pointer="true" />
    <rule avp="Destination-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="User-Identity" required="true" max="1" />
    <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true"/>
    <rule avp="Wildcarded-IMPU" required="false" max="1" pointer="true" />
    <rule avp="User-Name" required="false" max="1" pointer="true" />
    <rule avp="Data-Reference" required="false" />
    <rule avp="User-Data" required="true" max="1" />
    <rule avp="OC-Supported-Features" required="false" max="1" pointer="true" />
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</request>
<answer>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1"  pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1" />
    <rule avp="Result-Code" required="false" max="1" pointer="true"/>
    <rule avp="Experimental-Result" required="false" max="1" pointer="true"/>
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Wildcarded-Public-Identity" required="false" max="1"  pointer="true"/>
    <rule avp="Wildcarded-IMPU" required="false" max="1" pointer="true" />
    <rule avp="Repository-Data-ID" required="false" max="1" pointer="true" />
    <rule avp="Data-Reference" required="false" max="1" pointer="true"/>
    <rule avp="Supported-Features" required="false" />
    <rule avp="OC-Supported-Features" required="false" max="1" pointer="true" />
    <rule avp="OC-OLR" required="false" max="1" pointer="true" />
    <rule avp="Load" required="false" />
    <rule avp="AVP" required="false" />
    <rule avp="Failed-AVP" required="false" max="1" pointer="true" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</answer>
</command>

<command code="308" short="SN" name="Subscribe-Notifications" >
    <request>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1"  />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="false" max="1" pointer="true" />
    <rule avp="Destination-Realm" required="true" max="1"  />
    <rule avp="Supported-Features" required="false" />
    <rule avp="User-Identity" required="true" max="1" />
    <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true" />
    <rule avp="Wildcarded-IMPU" required="false" max="1" pointer="true" />
    <rule avp="Service-Indication" required="false" />
    <rule avp="Send-Data-Indication" required="false" max="1" pointer="true" />
    <rule avp="Server-Name" required="false" max="1" pointer="true" />
    <rule avp="Subs-Req-Type" required="true" max="1" />
    <rule avp="Data-Reference" required="true" />
    <rule avp="Identity-Set" required="false" />
    <rule avp="Expiry-Time" required="false" max="1" pointer="true" />
    <rule avp="DSAI-Tag" required="false" />
    <rule avp="One-Time-Notification" required="false" max="1" pointer="true" />
    <rule avp="User-Name" required="false" max="1" pointer="true" />
    <rule avp="OC-Supported-Features" required="false" max="1" pointer="true" />
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
    </request>
<answer>

    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Result-Code" required="false" max="1" pointer="true" />
    <rule avp="Experimental-Result" required="false" max="1" pointer="true" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true" />
    <rule avp="Wildcarded-IMPU" required="false" max="1" pointer="true" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="User-Data" required="true" max="1"/>
    <rule avp="Expiry-Time" required="false" max="1" pointer="true" />
    <rule avp="OC-Supported-Features" required="false" max="1" pointer="true" />
    <rule avp="OC-OLR" required="false" max="1" pointer="true" />
    <rule avp="Load" required="false" />
    <rule avp="AVP" required="false" />
    <rule avp="Failed-AVP" required="false" max="1" pointer="true" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</answer>
</command>

<command code="309" short="PN" name="Push-Notifications">
    <request>
    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Destination-Host" required="true" max="1" />
    <rule avp="Destination-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="User-Identity" required="true" max="1"/>
    <rule avp="Wildcarded-Public-Identity" required="false" max="1" pointer="true" />
    <rule avp="Wildcarded-IMPU" required="false" max="1" pointer="true" />
    <rule avp="User-Name" required="false" max="1" pointer="true" />
    <rule avp="User-Data" required="true" max="1"/>
    <rule avp="AVP" required="false" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
    </request>
<answer>

    <rule avp="Session-Id" required="true" max="1" />
    <rule avp="DRMP" required="false" max="1" pointer="true" />
    <rule avp="Vendor-Specific-Application-Id" required="true" max="1" />
    <rule avp="Result-Code" required="false" max="1" pointer="true" />
    <rule avp="Experimental-Result" required="false" max="1" pointer="true" />
    <rule avp="Auth-Session-State" required="true" max="1" />
    <rule avp="Origin-Host" required="true" max="1" />
    <rule avp="Origin-Realm" required="true" max="1" />
    <rule avp="Supported-Features" required="false" />
    <rule avp="AVP" required="false" />
    <rule avp="Failed-AVP" required="false" max="1" pointer="true" />
    <rule avp="Proxy-Info" required="false" />
    <rule avp="Route-Record" required="false" />
</answer>
</command>

<avp name="Session-Id" code="263" must="M" may="P" must-not="V" may-encrypt="Y">
    <data type="UTF8String"/>
</avp>

<avp name="DRMP" code="301" must-not="V">
    <data type="Enumerated">
        <item code="0" name="PRIORITY_0"/>
        <item code="1" name="PRIORITY_1"/>
        <item code="2" name="PRIORITY_2"/>
        <item code="3" name="PRIORITY_3"/>
        <item code="4" name="PRIORITY_4"/>
        <item code="5" name="PRIORITY_5"/>
        <item code="6" name="PRIORITY_6"/>
        <item code="7" name="PRIORITY_7"/>
        <item code="8" name="PRIORITY_8"/>
        <item code="9" name="PRIORITY_9"/>
        <item code="10" name="PRIORITY_10"/>
        <item code="11" name="PRIORITY_11"/>
        <item code="12" name="PRIORITY_12"/>
        <item code="13" name="PRIORITY_13"/>
        <item code="14" name="PRIORITY_14"/>
        <item code="15" name="PRIORITY_15"/>
    </data>
</avp>

<avp name="Vendor-Specific-Application-Id" code="260" must="M" may="P" must-not="V" may-encrypt="N" vendor-id="10415">
    <data type="Grouped" >
        <rule avp="Vendor-ID" required="false" max="1" />
        <rule avp="Auth-Application-Id" required="false" max="1" />
        <rule avp="Acct-Application-Id" required="false" max="1" />
    </data>
</avp>

<avp name="Vendor-ID" code="266" must="M" may-encrypt="-" vendor-id="10415">
    <data type="Unsigned32"   />
</avp>

<avp name="Auth-Application-Id" code="258" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Unsigned32"    />
</avp>

<avp name="Acct-Application-Id" code="259" must="M" may="P" must-not="V" may-encrypt="N">
    <data type="Unsigned32"    />
</avp>

<avp name="Auth-Session-State" code="277" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Enumerated">
        <item code="0" name="STATE_MAINTAINED"/>
        <item code="1" name="NO_STATE_MAINTAINED"/>
    </data>
</avp>

<avp name="Origin-Host" code="264" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="Origin-Realm" code="296" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="Destination-Host" code="293" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="Destination-Realm" code="283" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="DiameterIdentity"/>
</avp>

<avp name="Supported-Features" code="628" must="V" may-encrypt="N" vendor-id="10415">
    <data type="Grouped"  >
        <rule avp="Vendor-ID" required="true" max="1" />
        <rule avp="Feature-List-ID" required="true" max="1" />
        <rule avp="Feature-List" required="true" max="1" />
    </data>
</avp>

<avp name="Vendor-ID" code="266" must="M" may-encrypt="-" vendor-id="10415">
    <data type="Unsigned32"   />
</avp>

<avp name="Feature-List-ID" code="629" must="V" may-encrypt="N" vendor-id="10415">
    <data type="Unsigned32"   />
</avp>

<avp name="Feature-List" code="630" must="V" may-encrypt="N" vendor-id="10415">
    <data type="Unsigned32"   />
</avp>

<avp name="User-Identity" code="700" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="Grouped"  >
        <rule avp="Public-Identity" required="false" max="1" pointer="true" />
        <rule avp="MSISDN" required="false" max="1" pointer="true" />
        <rule avp="External-Identifier" required="false" max="1" pointer="true" />
    </data>
</avp>

<avp name="Public-Identity" code="601" must="M,V" may-encrypt="N" vendor-id="10415">
    <data type="UTF8String"   />
</avp>

<avp name="MSISDN" code="701" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="OctetString"   />
</avp>

<avp name="External-Identifier" code="3111" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="UTF8String"   />
</avp>

<avp name="Wildcarded-Public-Identity" code="634" must="V" must-not="M" may-encrypt="N">
    <data type="UTF8String"   />
</avp>

<avp name="Wildcarded-IMPU" code="636" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="UTF8String"   />
</avp>

<avp name="Server-Name" code="602" must="M,V" may="-" must-not="-" may-encrypt="-">
    <data type="UTF8String"   />
</avp>

<avp name="Service-Indication" code="704" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="UTF8String"   />
</avp>

<avp name="Data-Reference" code="703" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Enumerated"  >
        <item code="0" name="RepositoryData" httpValue="RepositoryData" />
        <item code="10" name="IMSPublicIdentity" httpValue="IMSPublicIdentity" />
        <item code="11" name="IMSUserState" httpValue="IMSUserState" />
        <item code="12" name="S-CSCFName" httpValue="S-CSCFName" />
        <item code="13" name="InitialFilterCriteria" httpValue="InitialFilterCriteria" />
        <item code="14" name="LocationInformation" httpValue="LocationInformation" />
        <item code="15" name="UserState" httpValue="UserState" />
        <item code="16" name="ChargingInformation" httpValue="ChargingInformation" />
        <item code="17" name="MSISDN" httpValue="MSISDN" />
        <item code="18" name="PSIActivation" httpValue="PSIActivation" />
        <item code="19" name="DSAI" httpValue="DSAI" />
        <item code="21" name="ServiceLevelTraceInfo" httpValue="ServiceLevelTraceInfo" />
        <item code="22" name="IPAddressSecureBindingInformation" httpValue="IPAddressSecureBindingInformation" />
        <item code="23" name="ServicePriorityLevel" httpValue="ServicePriorityLevel" />
        <item code="24" name="SMSRegistrationInfo" httpValue="SMSRegistrationInfo" />
        <item code="25" name="UEReachabilityForIP" httpValue="UEReachabilityForIP" />
        <item code="26" name="TADSinformation" httpValue="TADSinformation" />
        <item code="27" name="STN-SR" httpValue="STN-SR" />
        <item code="28" name="UE-SRVCC-Capability" httpValue="UE-SRVCC-Capability" />
        <item code="29" name="ExtendedPriority" httpValue="ExtendedPriority" />
        <item code="30" name="CSRN" httpValue="CSRN" />
        <item code="31" name="ReferenceLocationInformation" httpValue="ReferenceLocationInformation" />
        <item code="32" name="IMSI" httpValue="IMSI" />
        <item code="33" name="IMSPrivateUserIdentity" httpValue="IMSPrivateUserIdentity" />
        <item code="34" name="IMEISV" httpValue="IMEISV" />
        <item code="35" name="UE-5G-SRVCC-Capability" httpValue="UE-5G-SRVCC-Capability" />
    </data>
</avp>

<avp name="Identity-Set" code="708" must="V" may="-" must-not="M" may-encrypt="N" >
    <data type="Enumerated"  >
        <item code="0" name="ALL_IDENTITIES" httpValue="ALL_IDENTITIES" />
        <item code="1" name="REGISTERED_IDENTITIES" httpValue="REGISTERED_IDENTITIES" />
        <item code="2" name="IMPLICIT_IDENTITIES" httpValue="IMPLICIT_IDENTITIES" />
        <item code="3" name="ALIAS_IDENTITIES" httpValue="ALIAS_IDENTITIES" />
    </data>
</avp>

<avp name="Requested-Domain" code="706" must="M,V" may="-" must-not="-" may-encrypt="N" >
    <data type="Enumerated"  >
        <item code="0" name="CS-Domain" httpValue="CS-Domain" />
        <item code="1" name="PS-Domain" httpValue="PS-Domain" />
    </data>
</avp>

<avp name="Current-Location" code="707" must="M,V" may="-" must-not="-" may-encrypt="N" >
    <data type="Enumerated"  >
        <item code="0" name="DoNotNeedInitiateActiveLocationRetrieval" httpValue="DoNotNeedInitiateActiveLocationRetrieval" />
        <item code="1" name="InitiateActiveLocationRetrieval" httpValue="InitiateActiveLocationRetrieval" />
    </data>
</avp>

<avp name="DSAI-Tag" code="711" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="OctetString"   />
</avp>

<avp name="Session-Priority" code="650" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
        <item code="0" name="PRIORITY-0" httpValue="PRIORITY-0"/>
        <item code="1" name="PRIORITY-1" httpValue="PRIORITY-1"/>
        <item code="2" name="PRIORITY-2" httpValue="PRIORITY-2"/>
        <item code="3" name="PRIORITY-3" httpValue="PRIORITY-3"/>
        <item code="4" name="PRIORITY-4" httpValue="PRIORITY-4"/>
    </data>
</avp>

<avp name="User-Name" code="1" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="10415">
    <data type="UTF8String"   />
</avp>

<avp name="Requested-Nodes" code="713" must="V" may="-" must-not="M" may-encrypt="N" vendor-id="10415">
    <data type="Unsigned32"   />
</avp>

<avp name="Serving-Node-Indication" code="714" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
        <item code="0" name="ONLY_SERVING_NODES_REQUIRED" httpValue="ONLY_SERVING_NODES_REQUIRED" />
    </data>
</avp>

<avp name="Pre-paging-Supported" code="717" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
        <item code="0" name="PREPAGING_NOT_SUPPORTED" httpValue="PREPAGING_NOT_SUPPORTED" />
        <item code="1" name="PREPAGING_SUPPORTED" httpValue="PREPAGING_SUPPORTED" />
    </data>
</avp>

<avp name="Local-Time-Zone-Indication" code="718" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
        <item code="0" name="ONLY_LOCAL_TIME_ZONE_REQUESTED" httpValue="ONLY_LOCAL_TIME_ZONE_REQUESTED" />
        <item code="1" name="LOCAL_TIME_ZONE_WITH_LOCATION_INFO_REQUESTED" httpValue="LOCAL_TIME_ZONE_WITH_LOCATION_INFO_REQUESTED" />
    </data>
</avp>

<avp name="UDR-Flags" code="719" must="M,V" may="-" must-not="-" may-encrypt="N" vendor-id="10415">
    <data type="Unsigned32"   />
</avp>

<avp name="Call-Reference-Info" code="720" must="V" may="-" must-not="M" may-encrypt="N" vendor-id="10415">
    <data type="Grouped"  >
        <rule avp="Call-Reference-Number" required="true" max="1" />
        <rule avp="AS-Number" required="true" max="1" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="Call-Reference-Number" code="721" must="V" may="-" must-not="M" may-encrypt="N" vendor-id="10415">
    <data type="OctetString"   />
</avp>

<avp name="AS-Number" code="722" must="V" may="-" must-not="M" may-encrypt="N" vendor-id="10415">
    <data type="OctetString"   />
</avp>

<avp name="OC-Supported-Features" code="621" must-not="V">
    <data type="Grouped"   >
        <rule avp="OC-Feature-Vector" required="false" max="1"/>
        <rule avp="AVP" required="false" />
    </data>
</avp>

		<avp name="OC-Feature-Vector" code="622" must-not="V">
			<data type="Unsigned64"/>
		</avp>

<avp name="Proxy-Info" code="284" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="Grouped"  >
        <rule avp="Proxy-Host" required="true" max="1" />
        <rule avp="Proxy-State" required="true" max="1" />
    </data>
</avp>

<avp name="Proxy-Host" code="280" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="DiameterIdentity" />
</avp>

<avp name="Proxy-State" code="33" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="OctetString"   />
</avp>

<avp name="Route-Record" code="282" must="M" may="-" must-not="P,V" may-encrypt="N">
    <data type="DiameterIdentity" />
</avp>

<avp name="Result-Code" code="268" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Unsigned32"  />
</avp>

<avp name="Experimental-Result" code="297" must="M" may="P" must-not="V" may-encrypt="N">
    <data type="Grouped"  >
        <rule avp="Vendor-ID" required="true" max="1"/>
        <rule avp="Experimental-Result-Code" required="true" max="1"/>
    </data>
</avp>

<avp name="Experimental-Result-Code" code="298" must="M" may="P" must-not="V" may-encrypt="N">
      <data type="Unsigned32"    />
</avp>

<avp name="OC-OLR" code="623" must-not="M,V">
    <data type="Grouped">
        <rule avp="OC-Sequence-Number" required="true" max="1"/>
        <rule avp="OC-Report-Type" required="true" max="1"/>
        <rule avp="OC-Reduction-Percentage" required="false" max="1"/>
        <rule avp="OC-Validity-Duration" required="false" max="1"/>
        <rule avp="AVP" required="false"/>
    </data>
</avp>

<avp name="OC-Sequence-Number" code="624" must-not="V">
    <data type="Unsigned64"/>
</avp>

<avp name="OC-Validity-Duration" code="625" must-not="V">
    <data type="Unsigned32"/>
</avp>

<avp name="OC-Report-Type" code="626" must-not="V">
    <data type="Enumerated">
        <item code="0" name="HOST_REPORT"/>
        <item code="1" name="REALM_REPORT"/>
    </data>
</avp>

<avp name="OC-Reduction-Percentage" code="627" must-not="V">
    <data type="Unsigned32" />
</avp>

<avp name="Load" code="650" must-not="V">
    <data type="Grouped">
        <rule avp="Load-Type" required="false" max="1" />
        <rule avp="Load-Value" required="false" max="1" />
        <rule avp="SourceID" required="false" max="1" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="Load-Value" code="652" must-not="V">
    <data type="Unsigned64" />
</avp>

<avp name="Load-Type" code="651" must-not="V">
    <data type="Enumerated">
        <item code="0" name="HOST" />
        <item code="1" name="PEER"/>
    </data>
</avp>

<avp name="SourceID" code="649" must-not="V">
    <data type="DiameterIdentity" />
</avp>

<avp name="Failed-AVP" code="279" must="M" may="P" must-not="V" may-encrypt="-">
    <data type="Grouped" />
</avp>

<avp name="User-Data" code="702" must="M,V" may-encrypt="-" vendor-id="10415">
    <data type="OctetString"   />
</avp>

<avp name="One-Time-Notification" code="712" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Enumerated"    >
        <item code="0" name="ONE_TIME_NOTIFICATION_REQUESTED"  httpValue="ONE_TIME_NOTIFICATION_REQUESTED" />
    </data>
</avp>

<avp name="Subs-Req-Type" code="705" must="M,V" may="-" must-not="-" may-encrypt="N">
    <data type="Enumerated"  >
        <item code="0" name="Subscribe"  httpValue="Subscribe" />
        <item code="1" name="Unsubscribe" httpValue="Unsubscribe" />
    </data>
</avp>

<avp name="Send-Data-Indication" code="710" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Enumerated"  >
        <item code="0" name="USER_DATA_NOT_REQUESTED" httpValue="USER_DATA_NOT_REQUESTED" />
        <item code="1" name="USER_DATA_REQUESTED" httpValue="USER_DATA_REQUESTED" />
    </data>
</avp>

<avp name="Repository-Data-ID" code="715" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Grouped"  >
        <rule avp="Service-Indication" required="true" max="1" />
        <rule avp="Sequence-Number" required="true" max="1" />
        <rule avp="AVP" required="false" />
    </data>
</avp>

<avp name="Sequence-Number" code="716" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Unsigned32"    />
</avp>
<avp name="Expiry-Time" code="709" must="V" may="-" must-not="M" may-encrypt="N">
    <data type="Time" />
</avp>

        </application>
</diameter>`

var tgppswxXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>
    <!--
        3GPP TS 29.273
        http://www.qtc.jp/3GPP/Specs/29273-920.pdf
    -->
    <application id="16777265" type="auth" name="TGPP SWX">
        <vendor id="10415" name="TGPP"/>
        <command code="303" short="MA" name="Multimedia-Authentication">
            <request>
                <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.2.1 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Host" required="false" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
                <rule avp="RAT-Type" required="false" max="1"/>
                <rule avp="ANID" required="false" max="1"/>
                <rule avp="Visited-Network-Identifier" required="false" max="1" />
                <rule avp="Terminal-Information" required="false" max="1"/>
                <rule avp="SIP-Auth-Data-Item" required="false" max="1"/>
                <rule avp="SIP-Number-Auth-Items" required="false" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="AVP" required="false"/>
            </request>
            <answer>
                <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.2.1 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
                <rule avp="Result-Code" required="false" max="1"/>
                <rule avp="Experimental-Result" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
                <rule avp="SIP-Number-Auth-Items" required="false" max="1"/>
                <rule avp="SIP-Auth-Data-Item" required="false"/>
                <rule avp="TGPP-AAA-Server-Name" required="false" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="AVP" required="false"/>
            </answer>
        </command>
        <command code="301" short="SA" name="Server-Assignment">
            <request>
                <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.2.3 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Host" required="false" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="Service-Selection" required="false" max="1"/>
                <rule avp="Context-Identifier" required="false" max="1"/>
                <rule avp="MIP6-Agent-Info" required="false" max="1"/>
                <rule avp="Visited-Network-Identifier" required="false" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
                <rule avp="Server-Assignment-Type" required="true" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="AVP" required="false"/>
            </request>
            <answer>
                <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.2.3 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
                <rule avp="Result-Code" required="false" max="1"/>
                <rule avp="Experimental-Result" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
                <rule avp="Non-3GPP-User-Data" required="false" max="1"/>
                <rule avp="TGPP-AAA-Server-Name" required="false" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="AVP" required="false"/>
            </answer>
        </command>
        <command code="304" short="RT" name="Registration-Termination">
            <request>
                <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.2.4 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="DRMP" required="false" max="1" />
                <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Destination-Host" required="false" max="1"/>
                <rule avp="Destination-Realm" required="true" max="1"/>
                <rule avp="User-Name" required="true" max="1"/>
                <rule avp="Deregistration-Reason" required="true" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="AVP" required="false"/>
            </request>
            <answer>
                <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.2.4 -->
                <rule avp="Session-Id" required="true" max="1"/>
                <rule avp="DRMP" required="false" max="1" />
                <rule avp="Vendor-Specific-Application-Id" required="true" max="1"/>
                <rule avp="Result-Code" required="false" max="1"/>
                <rule avp="Experimental-Result" required="false" max="1"/>
                <rule avp="Auth-Session-State" required="true" max="1"/>
                <rule avp="Origin-Host" required="true" max="1"/>
                <rule avp="Origin-Realm" required="true" max="1"/>
                <rule avp="Supported-Features" required="false"/>
                <rule avp="AVP" required="false"/>
            </answer>
        </command>

        <avp name="RAT-Type" code="1032" must="M,V" may="P" may-encrypt="Y" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 5.2.3.6 -->
            <data type="Enumerated">
                <item code="0" name="WLAN"/>
                <item code="1" name="VIRTUAL"/>
                <item code="1000" name="UTRAN"/>
                <item code="1001" name="GERAN"/>
                <item code="1002" name="GAN"/>
                <item code="1003" name="HSPA_EVOLUTION"/>
                <item code="1004" name="EUTRAN"/>
                <item code="2000" name="CDMA2000_1X"/>
                <item code="2001" name="HRPD"/>
                <item code="2002" name="UMB"/>
                <item code="2003" name="EHRPD"/>
            </data>
        </avp>

        <avp name="ANID" code="1504" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 5.2.3.7 -->
            <data type="UTF8String"/>
        </avp>

        <avp name="Visited-Network-Identifier" code="600" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 9.2.3.1.2 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Terminal-Information" code="1401" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.3 -->
            <data type="Grouped">
                <rule avp="IMEI" required="false" max="1"/>
                <rule avp="TGPP2-MEID" required="false" max="1"/>
                <rule avp="Software-Version" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="SIP-Auth-Data-Item" code="612" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.9-->
            <data type="Grouped">
                <rule avp="SIP-Item-Number" required="false" max="1"/>
                <rule avp="SIP-Authentication-Scheme" required="false" max="1"/>
                <rule avp="SIP-Authenticate" required="false" max="1"/>
                <rule avp="SIP-Authorization" required="false" max="1"/>
                <rule avp="Confidentiality-Key" required="false" max="1"/>
                <rule avp="Integrity-Key" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="SIP-Item-Number" code="613" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.229 Section 6.3.14 -->
            <data type="Unsigned32"/>
        </avp>

        <avp name="SIP-Authentication-Scheme" code="608" must="M,V" may-encrypt="N" vendor-id="10415">
             <!-- 3GPP TS 29.229 Section 6.3.9 -->
            <data type="UTF8String"/>
        </avp>

        <avp name="SIP-Authenticate" code="609" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.229 Section 6.3.10 -->
            <data type="OctetString"/>
        </avp>

        <avp name="SIP-Authorization" code="610" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.229 Section 6.3.11 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Confidentiality-Key" code="625" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.10 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Integrity-Key" code="626" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.11 -->
            <data type="OctetString"/>
        </avp>

        <avp name="SIP-Number-Auth-Items" code="607" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.229 Section 6.3.8 -->
            <data type="Unsigned32" />
        </avp>

        <avp name="TGPP-AAA-Server-Name" code="318" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.234 Section 10.1.34 -->
            <data type="DiameterIdentity"/>
        </avp>

        <avp name="Supported-Features" code="628" vendor-id="10415" must="V" may="M" may-encrypt="N">
            <!-- 3GPP TS 29.229 Section 6.3.29 -->
            <data type="Grouped">
                <rule avp="Vendor-Id" required="true" max="1"/>
                <rule avp="Feature-List-ID" required="true" max="1"/>
                <rule avp="Feature-List" required="true" max="1"/>
            </data>
        </avp>

        <avp name="Service-Selection" code="493" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="0">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 5.2.3.5 -->
            <data type="UTF8String"/>
        </avp>

        <avp name="Context-Identifier" code="1423" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.27 -->
            <data type="Unsigned32"/>
        </avp>

        <!-- RFC 5447 Diameter Mobile IPv6: Support for Network Access Server to Diameter Server Interaction -->
        <avp name="MIP6-Agent-Info" code="486" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="10415">
            <data type="Grouped">
                <rule avp="MIP-Home-Agent-Address" required="false" max="2"/>
                <rule avp="MIP-Home-Agent-Host" required="false" max="1"/>
                <rule avp="MIP6-Home-Link-Prefix" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Server-Assignment-Type" code="614" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.12 -->
            <data type="Enumerated">
                <item code="0" name="NO_ASSIGNMENT"/>
                <item code="1" name="REGISTRATION"/>
                <item code="2" name="RE_REGISTRATION"/>
                <item code="3" name="UNREGISTERED_USER"/>
                <item code="4" name="TIMEOUT_DEREGISTRATION"/>
                <item code="5" name="USER_DEREGISTRATION"/>
                <item code="6" name="TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME"/>
                <item code="7" name="USER_DEREGISTRATION_STORE_SERVER_NAME"/>
                <item code="8" name="ADMINISTRATIVE_DEREGISTRATION"/>
                <item code="9" name="AUTHENTICATION_FAILURE"/>
                <item code="10" name="AUTHENTICATION_TIMEOUT"/>
                <item code="11" name="DEREGISTRATION_TOO_MUCH_DATA"/>
                <item code="12" name="AAA_USER_DATA_REQUEST"/>
                <item code="13" name="PGW_UPDATE"/>
                <item code="14" name="RESTORATION"/>
            </data>
        </avp>

        <avp name="Deregistration-Reason" code="615" must="M,V" may-encrypt="N" vendor-id="10415">
             <!-- https://www.etsi.org/deliver/etsi_ts/129200_129299/129229/10.05.00_60/ts_129229v100500p.pdf -->
             <data type="Grouped">
                <rule avp="Reason-Code" required="true"/>
                <rule avp="Reason-Info" required="false"/>
                <rule avp="AVP" required="false"/>
             </data>
        </avp>

        <avp name="Reason-Code" code="616" must="M,V" may-encrypt="N" vendor-id="10415">
             <!-- https://www.etsi.org/deliver/etsi_ts/129200_129299/129229/10.05.00_60/ts_129229v100500p.pdf -->
             <data type="Enumerated">
                <item code="0" name="PERMANENT_TERMINATION"/>
                <item code="1" name="NEW_SERVER_ASSIGNMENT"/>
                <item code="2" name="SERVER_CHANGE"/>
                <item code="3" name="REMOVE_S_CSCF"/>
             </data>
        </avp>

        <avp name="Reason-Info" code="617" must="M,V" may-encrypt="N" vendor-id="10415">
             <!-- https://www.etsi.org/deliver/etsi_ts/129200_129299/129229/10.05.00_60/ts_129229v100500p.pdf -->
             <data type="UTF8String"/>
        </avp>

        <avp name="Non-3GPP-User-Data" code="1500" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.1 -->
            <data type="Grouped">
                <rule avp="Subscription-Id" required="false" max="1"/>
                <rule avp="Non-3GPP-IP-Access" required="false" max="1"/>
                <rule avp="Non-3GPP-IP-Access-APN" required="false" max="1"/>
                <rule avp="RAT-Type" required="false"/>
                <rule avp="Session-Timeout" required="false" max="1"/>
                <rule avp="MIP6-Feature-Vector" required="false" max="1"/>
                <rule avp="AMBR" required="false" max="1"/>
                <rule avp="3GPP-Charging-Characteristics" required="false" max="1"/>
                <rule avp="Context-Identifier" required="false" max="1"/>
                <rule avp="APN-OI-Replacement" required="false" max="1"/>
                <rule avp="APN-Configuration" required="false"/>
                <rule avp="Trace-Info" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Subscription-Id" code="443" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="0">
            <!-- https://tools.ietf.org/rfc/rfc4006.txt -->
            <data type="Grouped">
                <rule avp="Subscription-Id-Type" required="false" max="1"/>
                <rule avp="Subscription-Id-Data" required="false" max="1"/>
            </data>
        </avp>

        <avp name="Subscription-Id-Type" code="450" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="0">
            <!-- https://tools.ietf.org/rfc/rfc4006.txt -->
            <data type="Enumerated">
                <item code="0" name="END_USER_E164"/>
                <item code="1" name="END_USER_IMSI"/>
                <item code="2" name="END_USER_SIP_URI"/>
                <item code="3" name="END_USER_NAI"/>
                <item code="4" name="END_USER_PRIVATE"/>
            </data>
        </avp>

        <avp name="Subscription-Id-Data" code="444" must="M" may="P" must-not="V" may-encrypt="Y" vendor-id="0">
            <!-- https://tools.ietf.org/rfc/rfc4006.txt -->
            <data type="UTF8String"/>
        </avp>

        <avp name="Non-3GPP-IP-Access" code="1501" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.3 -->
            <data type="Enumerated">
                <item code="0" name="NON_3GPP_SUBSCRIPTION_ALLOWED"/>
                <item code="1" name="NON_3GPP_SUBSCRIPTION_BARRED"/>
            </data>
        </avp>

        <avp name="Non-3GPP-IP-Access-APN" code="1502" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.4 -->
            <data type="Enumerated">
                <item code="0" name="NON_3GPP_APNS_ENABLE"/>
                <item code="1" name="NON_3GPP_APNS_DISABLE"/>
            </data>
        </avp>

        <avp name="MIP6-Feature-Vector" code="124" must="M" may="P" may-encrypt="N" vendor-id="0">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 5.2.3.3 -->
            <data type="Unsigned64"/>
        </avp>

        <avp name="AMBR" code="1435" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.41 -->
            <data type="Grouped">
                <rule avp="Max-Requested-Bandwidth-UL" required="true" max="1"/>
                <rule avp="Max-Requested-Bandwidth-DL" required="true" max="1"/>
                <rule avp="Extended-Max-Requested-BW-UL" required="true" max="1"/>
                <rule avp="Extended-Max-Requested-BW-DL" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Max-Requested-Bandwidth-DL" code="515" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.214 [11] -->
            <data type="Unsigned32"/>
        </avp>

        <avp name="Max-Requested-Bandwidth-UL" code="516" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.214 [11] -->
            <data type="Unsigned32"/>
        </avp>

		<avp name="Extended-Max-Requested-BW-DL" code="554" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Extended-Max-Requested-BW-UL" code="555" must="V"	may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

        <avp name="TGPP-Charging-Characteristics" code="13" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.061 [21] -->
            <data type="UTF8String"/>
        </avp>


        <avp name="APN-OI-Replacement" code="1427" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.32 -->
            <data type="UTF8String"/>
        </avp>

        <avp name="APN-Configuration" code="1430" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.35 -->
            <data type="Grouped">
                <rule avp="Context-Identifier" required="true" max="1"/>
                <rule avp="Served-Party-IP-Address" required="false" max="2"/>
                <rule avp="PDN-Type" required="true" max="1"/>
                <rule avp="Service-Selection" required="true" max="1"/>
                <rule avp="EPS-Subscribed-QoS-Profile" required="false" max="1"/>
                <rule avp="VPLMN-Dynamic-Address-Allowed" required="false" max="1"/>
                <rule avp="MIP6-Agent-Info" required="false" max="1"/>
                <rule avp="Visited-Network-Identifier" required="false" max="1"/>
                <rule avp="PDN-GW-Allocation-Type" required="false" max="1"/>
                <rule avp="TGPP-Charging-Characteristics" required="false" max="1"/>
                <rule avp="AMBR" required="false" max="1"/>
                <rule avp="Specific-APN-Info" required="false"/>
                <rule avp="APN-OI-Replacement" required="false" max="1"/>
                <rule avp="SIPTO-Permission" required="false" max="1"/>
                <rule avp="LIPA-Permission" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Served-Party-IP-Address" code="848" must="M,V" may="P" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 32.299 [8] -->
            <data type="Address"/>
        </avp>

        <avp name="PDN-Type" code="1456" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.62 -->
            <data type="Enumerated">
                <item code="0" name="IPv4"/>
                <item code="1" name="IPv6"/>
                <item code="2" name="IPv4v6"/>
                <item code="3" name="IPv4_OR_IPv6"/>
            </data>
        </avp>

        <avp name="EPS-Subscribed-QoS-Profile" code="1431" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.37 -->
            <data type="Grouped">
                <rule avp="QoS-Class-Identifier" required="true" max="1"/>
                <rule avp="Allocation-Retention-Priority" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="QoS-Class-Identifier" code="1028" must="V,M" may="P" must-not="-" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.212 [10] -->
            <data type="Enumerated">
                <item code="1" name="QCI_1"/>
                <item code="2" name="QCI_2"/>
                <item code="3" name="QCI_3"/>
                <item code="4" name="QCI_4"/>
                <item code="5" name="QCI_5"/>
                <item code="6" name="QCI_6"/>
                <item code="7" name="QCI_7"/>
                <item code="8" name="QCI_8"/>
                <item code="9" name="QCI_9"/>
                <item code="65" name="QCI_65"/>
                <item code="66" name="QCI_66"/>
                <item code="69" name="QCI_69"/>
                <item code="70" name="QCI_70"/>
                <item code="75" name="QCI_75"/>
                <item code="79" name="QCI_79"/>
            </data>
        </avp>

        <avp name="Allocation-Retention-Priority" code="1034" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.212 [10] -->
            <data type="Grouped">
                <rule avp="Priority-Level" required="true" max="1"/>
                <rule avp="Pre-emption-Capability" required="false" max="1"/>
                <rule avp="Pre-emption-Vulnerability" required="false" max="1"/>
            </data>
        </avp>

        <avp name="Priority-Level" code="1046" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.212 [10] -->
            <data type="Unsigned32"/>
        </avp>

        <avp name="Pre-emption-Capability" code="1047" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.212 [10] -->
            <data type="Enumerated">
                <item code="0" name="PRE-EMPTION_CAPABILITY_ENABLED"/>
                <item code="1" name="PRE-EMPTION_CAPABILITY_DISABLED"/>
            </data>
        </avp>

        <avp name="Pre-emption-Vulnerability" code="1048" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            <!-- 3GPP TS 29.212 [10] -->
            <data type="Enumerated">
                <item code="0" name="PRE-EMPTION_VULNERABILITY_ENABLED"/>
                <item code="1" name="PRE-EMPTION_VULNERABILITY_DISABLED"/>
            </data>
        </avp>

        <avp name="VPLMN-Dynamic-Address-Allowed" code="1432" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.38 -->
            <data type="Enumerated">
                <item code="0" name="NOTALLOWED"/>
                <item code="1" name="ALLOWED"/>
            </data>
        </avp>

        <avp name="PDN-GW-Allocation-Type" code="1438" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.44 -->
            <data type="Enumerated">
                <item code="0" name="STATIC"/>
                <item code="1" name="DYNAMIC"/>
            </data>
        </avp>

        <avp name="Specific-APN-Info" code="1472" vendor-id="10415" must="M,V" may-encrypt="N">
            <!-- 3GPP TS 29.272 Section 7.3.82 -->
            <data type="Grouped">
                <rule avp="Service-Selection" required="true" max="1"/>
                <rule avp="MIP6-Agent-Info" required="true" max="1"/>
                <rule avp="Visited-Network-Identifier" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="SIPTO-Permission" code="1613" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.135 -->
            <data type="Enumerated">
                <item code="0" name="SIPTO_ALLOWED"/>
                <item code="1" name="SIPTO_NOTALLOWED"/>
            </data>
        </avp>

        <avp name="LIPA-Permission" code="1618" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.132 -->
            <data type="Enumerated">
                <item code="0" name="LIPA-PROHIBITED"/>
                <item code="1" name="LIPA-ONLY"/>
                <item code="2" name="LIPA-CONDITIONAL"/>
            </data>
        </avp>

        <avp name="Trace-Info" code="1505" must="V" must-not="M" vendor-id="10415">
            <!-- http://www.qtc.jp/3GPP/Specs/29273-920.pdf Section 8.2.3.13 -->
            <data type="Grouped">
                <rule avp="Trace-Data" required="false" max="1"/>
                <rule avp="Trace-Reference" required="false" max="1"/>
            </data>
        </avp>

        <avp name="Trace-Data" code="1458" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.63 -->
            <data type="Grouped">
                <rule avp="Trace-Reference" required="true" max="1"/>
                <rule avp="Trace-Depth" required="true" max="1"/>
                <rule avp="Trace-NE-Type-List" required="true" max="1"/>
                <rule avp="Trace-Interface-List" required="false" max="1"/>
                <rule avp="Trace-Event-List" required="true" max="1"/>
                <rule avp="OMC-Id" required="false" max="1"/>
                <rule avp="Trace-Collection-Entity" required="true" max="1"/>
                <rule avp="MDT-Configuration" required="false" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

        <avp name="Trace-Reference" code="1459" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.64 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Depth" code="1462" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.67 -->
            <data type="Enumerated">
                <item code="0" name="LIPA-PROHIBITED"/>
                <item code="1" name="LIPA-ONLY"/>
                <item code="2" name="LIPA-CONDITIONAL"/>
            </data>
        </avp>

        <avp name="Trace-NE-Type-List" code="1463" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.68 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Interface-List" code="1464" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.69 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Event-List" code="1465" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.70 -->
            <data type="OctetString"/>
        </avp>

        <avp name="OMC-Id" code="1466" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.71 -->
            <data type="OctetString"/>
        </avp>

        <avp name="Trace-Collection-Entity" code="1452" must="M,V" may="P" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.98 -->
            <data type="Address"/>
        </avp>

        <avp name="MDT-Configuration" code="1622" must="M,V" may-encrypt="N" vendor-id="10415">
            <!-- 3GPP TS 29.272 Section 7.3.136 -->
            <data type="Grouped">
                <rule avp="QoS-Class-Identifier" required="true" max="1"/>
                <rule avp="Allocation-Retention-Priority" required="true" max="1"/>
                <rule avp="AVP" required="false"/>
            </data>
        </avp>

    </application>
</diameter>`
var tgpprxXML = `<?xml version="1.0" encoding="UTF-8"?>
<diameter>

	<!--
		3GPP TS 29.214
		See: https://www.3gpp.org/ftp//Specs/archive/29_series/29.214/29214-g40.zip
	-->
	<application id="16777236" type="auth" name="Rx">
        <vendor id="10415" name="TGPP"/>
        <command code="265" short="AA" name="AA">
			<request>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="IP-Domain-Id" required="false" max="1"/>
				<rule avp="Auth-Session-State" required="false" max="1"/>
				<rule avp="AF-Application-Identifier" required="false" max="1"/>
				<rule avp="Media-Component-Description" required="false"/>
				<rule avp="Service-Info-Status" required="false" max="1"/>
				<rule avp="AF-Charging-Identifier" required="false" max="1"/>
				<rule avp="SIP-Forking-Indication " required="false" max="1"/>
				<rule avp="Specific-Action" required="false"/>
				<rule avp="Subscription-Id" required="false"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="Supported-Features" required="false"/>
				<rule avp="Reservation-Priority" required="false" max="1"/>
				<rule avp="Framed-IP-Address" required="false" max="1"/>
				<rule avp="Framed-Ipv6-Prefix" required="false" max="1"/>
				<rule avp="Called-Station-Id" required="false" max="1"/>
				<rule avp="Service-URN" required="false" max="1"/>
				<rule avp="Sponsored-Connectivity-Data " required="false" max="1"/>
				<rule avp="MPS-Identifier" required="false" max="1"/>
				<rule avp="GCS-Identifier" required="false" max="1"/>
				<rule avp="MCPTT-Identifier" required="false" max="1"/>
				<rule avp="MCVideo-Identifier" required="false" max="1"/>
				<rule avp="IMS-Content-Identifier" required="false" max="1"/>
				<rule avp="IMS-Content-Type" required="false" max="1"/>
				<rule avp="Calling-Party-Address" required="false"/>
				<rule avp="Callee-Information" required="false" max="1"/>
				<rule avp="Rx-Request-Type" required="false" max="1"/>
				<rule avp="Required-Access-Info" required="false"/>
				<rule avp="AF-Requested-Data" required="false" max="1"/>
				<rule avp="Reference-Id" required="false" max="1"/>
				<rule avp="Pre-emption-Control-Info" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
				<rule avp="AVP" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Result-Code" required="false" max="1"/>
				<rule avp="Experimental-Result" required="false" max="1"/>
				<rule avp="Auth-Session-State" required="false" max="1"/>
				<rule avp="Access-Network-Charging-Identifier" required="false"/>
				<rule avp="Access-Network-Charging-Address" required="false" max="1"/>
				<rule avp="Acceptable-Service-Info" required="false" max="1"/>
				<rule avp="AN-GW-Address" required="false"/>
				<rule avp="AN-Trusted" required="false" max="1"/>
				<rule avp="Service-Authorization-Info" required="false" max="1"/>
				<rule avp="IP-CAN-Type" required="false" max="1"/>
				<rule avp="MA-Information" required="false" max="1"/>
				<rule avp="NetLoc-Access-Support" required="false" max="1"/>
				<rule avp="RAT-Type" required="false" max="1"/>
				<rule avp="Flows" required="false"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="OC-OLR" required="false" max="1"/>
				<rule avp="Supported-Features" required="false"/>
				<rule avp="Subscription-Id" required="false"/>
				<rule avp="User-Equipment-Info" required="false" max="1"/>
				<rule avp="3GPP-SGSN-MCC-MNC" required="false" max="1"/>
				<rule avp="NID" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Retry-Interval" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Load" required="false"/>
				<rule avp="AVP" required="false"/>
			</answer>
		</command>

		<command code="258" short="RA" name="Re-Auth">
			<request>
				<rule avp="Session-Id " required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Destination-Host" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Specific-Action" required="true"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="Access-Network-Charging-Identifier" required="false"/>
				<rule avp="Access-Network-Charging-Address" required="false" max="1"/>
				<rule avp="AN-GW-Address" required="false"/>
				<rule avp="AN-Trusted" required="false" max="1"/>
				<rule avp="Flows" required="false"/>
				<rule avp="Subscription-Id" required="false"/>
				<rule avp="Abort-Cause" required="false" max="1"/>
				<rule avp="IP-CAN-Type" required="false" max="1"/>
				<rule avp="MA-Information" required="false" max="1"/>
				<rule avp="NetLoc-Access-Support" required="false" max="1"/>
				<rule avp="RAT-Type" required="false" max="1"/>
				<rule avp="Sponsored-Connectivity-Data" required="false" max="1"/>
				<rule avp="3GPP-User-Location-Info" required="false" max="1"/>
				<rule avp="User-Location-Info-Time" required="false" max="1"/>
				<rule avp="3GPP-MS-TimeZone" required="false" max="1"/>
				<rule avp="RAN-NAS-Release-Cause" required="false"/>
				<rule avp="FiveGS-RAN-NAS-Release-Cause" required="false"/>
				<rule avp="3GPP-SGSN-MCC-MNC" required="false" max="1"/>
				<rule avp="NID" required="false" max="1"/>
				<rule avp="TWAN-Identifier" required="false" max="1"/>
				<rule avp="TCP-Source-Port" required="false" max="1"/>
				<rule avp="UDP-Source-Port" required="false" max="1"/>
				<rule avp="UE-Local-IP-Address" required="false" max="1"/>
				<rule avp="Wireline-User-Location-Info" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
				<rule avp="AVP" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Result-Code" required="false" max="1"/>
				<rule avp="Experimental-Result" required="false" max="1"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="OC-OLR" required="false" max="1"/>
				<rule avp="Media-Component-Description" required="false"/>
				<rule avp="Service-URN" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="AVP" required="false"/>
			</answer>
		</command>

		<command code="275" short="ST" name="Session-Termination">
			<request>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="Termination-Cause" required="true" max="1"/>
				<rule avp="Destination-Host" required="false" max="1"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="Required-Access-Info" required="false"/>
				<rule avp="Class" required="false"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
				<rule avp="AVP" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Result-Code" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="OC-OLR" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Sponsored-Connectivity-Data" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="3GPP-User-Location-Info" required="false" max="1"/>
				<rule avp="User-Location-Info-Time" required="false" max="1"/>
				<rule avp="3GPP-MS-TimeZone" required="false" max="1"/>
				<rule avp="RAN-NAS-Release-Cause" required="false"/>
				<rule avp="FiveGS-RAN-NAS-Release-Cause" required="false"/>
				<rule avp="3GPP-SGSN-MCC-MNC" required="false" max="1"/>
				<rule avp="NID" required="false" max="1"/>
				<rule avp="TWAN-Identifier" required="false" max="1"/>
				<rule avp="TCP-Source-Port" required="false" max="1"/>
				<rule avp="UDP-Source-Port" required="false" max="1"/>
				<rule avp="UE-Local-IP-Address" required="false" max="1"/>
				<rule avp="Netloc-Access-Support" required="false" max="1"/>
				<rule avp="Wireline-User-Location-Info" required="false" max="1"/>
				<rule avp="Class" required="false"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Load" required="false"/>
				<rule avp="AVP" required="false"/>
			</answer>
		</command>

		<command code="274" short="AS" name="Abort-Session">
			<request>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Destination-Realm" required="true" max="1"/>
				<rule avp="Destination-Host" required="true" max="1"/>
				<rule avp="Auth-Application-Id" required="true" max="1"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="Abort-Cause" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="Route-Record" required="false"/>
				<rule avp="AVP" required="false"/>
			</request>
			<answer>
				<rule avp="Session-Id" required="true" max="1"/>
				<rule avp="DRMP" required="false" max="1"/>
				<rule avp="Origin-Host" required="true" max="1"/>
				<rule avp="Origin-Realm" required="true" max="1"/>
				<rule avp="Result-Code" required="false" max="1"/>
				<rule avp="OC-Supported-Features" required="false" max="1"/>
				<rule avp="OC-OLR" required="false" max="1"/>
				<rule avp="Origin-State-Id" required="false" max="1"/>
				<rule avp="Error-Message" required="false" max="1"/>
				<rule avp="Error-Reporting-Host" required="false" max="1"/>
				<rule avp="Failed-AVP" required="false" max="1"/>
				<rule avp="Redirect-Host" required="false"/>
				<rule avp="Redirect-Host-Usage" required="false" max="1"/>
				<rule avp="Redirect-Max-Cache-Time" required="false" max="1"/>
				<rule avp="Proxy-Info" required="false"/>
				<rule avp="AVP" required="false"/>
			</answer>
		</command>
	
  		<avp name="Load" code="650" must-not="V">
    			<data type="Grouped"  >
      				<rule avp="Load-Type" required="false" max="1"/>
      				<rule avp="Load-Value" required="false" max="1"/>
      				<rule avp="SourceID" required="false" max="1"/>
      				<rule avp="AVP" required="false"/>
    			</data>
  		</avp>

  		<avp name="Load-Value" code="652" must-not="V">
    			<data type="Unsigned64"/>
  		</avp>

  		<avp name="Load-Type" code="651" must-not="V">
    			<data type="Enumerated"  >
      				<item code="0" name="HOST"/>
      				<item code="1" name="PEER"/>
    			</data>
  		</avp>

		<avp name="SourceID" code="649" must-not="V">
    			<data type="DiameterIdentity" />
		</avp>

		<avp name="FiveGS-RAN-NAS-Release-Cause" code="572" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="FiveGMM-Cause" required="false" max="1"/>
				<rule avp="FiveGSM-Cause" required="false" max="1"/>
				<rule avp="NGAP-Cause" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="FiveGMM-Cause" code="573" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="FiveGSM-Cause" code="574" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="NGAP-Cause" code="575" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="NGAP-Group" required="true" max="1"/>
				<rule avp="NGAP-Value" required="true" max="1"/>
			</data>
		</avp>
		
		<avp name="NGAP-Group" code="576" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="NGAP-Value" code="577" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Abort-Cause" code="500" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="BEARER_RELEASED"/>
				<item code="1" name="INSUFFICIENT_SERVER_RESOURCES"/>
				<item code="2" name="INSUFFICIENT_BEARER_RESOURCES"/>
				<item code="3" name="PS_TO_CS_HANDOVER"/>
				<item code="4" name="SPONSORED_DATA_CONNECTIVITY_DISALLOWED"/>
			</data>
		</avp>
		
		<avp name="Access-Network-Charging-Address" code="501" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Address"/>
		</avp>
		
		<avp name="Access-Network-Charging-Identifier" code="502" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="Access-Network-Charging-Identifier-Value" required="true" max="1"/>
				<rule avp="Flows" required="false"/>
			</data>
		</avp>
		
		<avp name="Access-Network-Charging-Identifier-Value" code="503" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="Flows" code="510" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="Media-Component-Number" required="true" max="1"/>
				<rule avp="Flow-Number" required="false"/>
				<rule avp="Content-Version" required="false"/>
				<rule avp="Final-Unit-Action" required="false" max="1"/>
				<rule avp="Media-Component-Status" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="Media-Component-Number" code="518" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Flow-Number" code="509" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Content-Version" code="552" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Media-Component-Status" code="549" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Acceptable-Service-Info" code="526" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="Media-Component-Description" required="false"/>
				<rule avp="Max-Requested-Bandwidth-DL" required="false" max="1"/>
				<rule avp="Max-Requested-Bandwidth-UL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-DL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-UL" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="Media-Component-Description" code="517" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="Media-Component-Number" required="true" max="1"/>
				<rule avp="Media-Sub-Component" required="false"/>
				<rule avp="AF-Application-Identifier" required="false" max="1"/>
				<rule avp="FLUS-Identifier" required="false" max="1"/>
				<rule avp="Media-Type" required="false" max="1"/>
				<rule avp="Max-Requested-Bandwidth-UL" required="false" max="1"/>
				<rule avp="Max-Requested-Bandwidth-DL" required="false" max="1"/>
				<rule avp="Max-Supported-Bandwidth-UL" required="false" max="1"/>
				<rule avp="Max-Supported-Bandwidth-DL" required="false" max="1"/>
				<rule avp="Min-Desired-Bandwidth-UL" required="false" max="1"/>
				<rule avp="Min-Desired-Bandwidth-DL" required="false" max="1"/>
				<rule avp="Min-Requested-Bandwidth-UL" required="false" max="1"/>
				<rule avp="Min-Requested-Bandwidth-DL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-UL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-DL" required="false" max="1"/>
				<rule avp="Extended-Max-Supported-BW-UL" required="false" max="1"/>
				<rule avp="Extended-Max-Supported-BW-UL" required="false" max="1"/>
				<rule avp="Extended-Min-Desired-BW-UL" required="false" max="1"/>
				<rule avp="Extended-Min-Desired-BW-DL" required="false" max="1"/>
				<rule avp="Extended-Min-Requested-BW-UL" required="false" max="1"/>
				<rule avp="Extended-Min-Requested-BW-DL" required="false" max="1"/>
				<rule avp="Flow-Status" required="false" max="1"/>
				<rule avp="Priority-Sharing-Indicator" required="false" max="1"/>
				<rule avp="Pre-emption-Capability" required="false" max="1"/>
				<rule avp="Pre-emption-Vulnerability" required="false" max="1"/>
				<rule avp="Reservation-Priority" required="false" max="1"/>
				<rule avp="RS-Bandwidth " required="false" max="1"/>
				<rule avp="RR-Bandwidth" required="false" max="1"/>
				<rule avp="Codec-Data" required="false"/>
				<rule avp="Sharing-Key-DL" required="false" max="1"/>
				<rule avp="Sharing-Key-UL" required="false" max="1"/>
				<rule avp="Content-Version" required="false" max="1"/>
				<rule avp="Max-PLR-DL" required="false" max="1"/>
				<rule avp="Max-PLR-UL" required="false" max="1"/>
				<rule avp="Desired-Max-Latency" required="false" max="1"/>
				<rule avp="Desired-Max-Loss" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="Max-Requested-Bandwidth-DL" code="515" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Max-Requested-Bandwidth-UL" code="516" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Extended-Max-Requested-BW-DL" code="554" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Extended-Max-Requested-BW-UL" code="555" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Media-Sub-Component" code="519" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="Flow-Number" required="true" max="1"/>
				<rule avp="Flow-Description" required="false"/>
				<rule avp="Flow-Status" required="false" max="1"/>
				<rule avp="Flow-Usage" required="false" max="1"/>
				<rule avp="Max-Requested-Bandwidth-UL" required="false" max="1"/>
				<rule avp="Max-Requested-Bandwidth-DL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-UL" required="false" max="1"/>
				<rule avp="Extended-Max-Requested-BW-DL" required="false" max="1"/>
				<rule avp="AF-Signalling-Protocol" required="false" max="1"/>
				<rule avp="ToS-Traffic-Class" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="Flow-Number" code="509" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Flow-Description" code="507" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="IPFilterRule"/>
		</avp>
		
		<avp name="Flow-Usage" code="512" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="NO_INFORMATION"/>
						<item code="1" name="RTCP"/>
				<item code="2" name="AF_SIGNALLING"/>
			</data>
		</avp>
		
		<avp name="AF-Signalling-Protocol" code="529" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="NO_INFORMATION"/>
				<item code="1" name="SIP"/>
			</data>
		</avp>
		
		<avp name="AF-Application-Identifier" code="504" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="FLUS-Identifier" code="566" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="Media-Type" code="520" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="AUDIO"/>
				<item code="1" name="VIDEO"/>
				<item code="2" name="DATA"/>
				<item code="3" name="APPLICATION"/>
				<item code="4" name="CONTROL"/>
				<item code="5" name="TEXT"/>
				<item code="6" name="MESSAGE"/>
			<!--	<item code="0xFFFFFFFF" name="OTHER"/>			-->
			</data>
		</avp>
		
		<avp name="Max-Supported-Bandwidth-UL" code="544" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Max-Supported-Bandwidth-DL" code="543" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Min-Desired-Bandwidth-DL" code="545" vendor-id="10415" must="V" may-encrypt="">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Min-Desired-Bandwidth-UL" code="546" vendor-id="10415" must="V" may-encrypt="">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Min-Requested-Bandwidth-DL" code="534" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Min-Requested-Bandwidth-UL" code="535" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Extended-Max-Supported-BW-DL" code="556" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Extended-Max-Supported-BW-UL" code="557" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Extended-Min-Desired-BW-DL" code="558" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Extended-Min-Desired-BW-UL" code="559" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Extended-Min-Requested-BW-DL" code="560" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Extended-Min-Requested-BW-UL" code="561" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Flow-Status" code="511" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="ENABLED-UPLINK"/>
				<item code="1" name="ENABLED-DOWNLINK"/>
				<item code="2" name="ENABLED"/>
				<item code="3" name="DISABLED"/>
				<item code="4" name="REMOVED"/>
			</data>
		</avp>
		
		<avp name="Priority-Sharing-Indicator" code="550" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="PRIORITY_SHARING_ENABLED"/>
				<item code="1" name="PRIORITY_SHARING_DISABLED"/>
			</data>
		</avp>
		
		<avp name="RS-Bandwidth" code="522" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="RR-Bandwidth" code="521" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Codec-Data" code="524" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="Sharing-Key-DL" code="539" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Sharing-Key-UL" code="540" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Desired-Max-Latency" code="567" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Float32"/>
		</avp>
		
		<avp name="Desired-Max-Loss" code="568" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Float32"/>
		</avp>
		
		<avp name="AF-Charging-Identifier" code="505" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="AF-Requested-Data" code="551" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Callee-Information" code="565" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="Called-Party-Address" required="true" max="1"/>
				<rule avp="Requested-Party-Address" required="false"/>
				<rule avp="Called-Asserted-Identity" required="false"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="GCS-Identifier" code="538" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="IP-Domain-Id" code="537" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="MA-Information" code="570" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="IP-CAN-Type" required="false" max="1"/>
				<rule avp="RAT-Type" required="false" mmax="1"/>
				<rule avp="MA-Information-Action" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="MA-Information-Action" code="571" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="MCPTT-Identifier" code="547" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="MCVideo-Identifier" code="562" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="MPS-Identifier" code="528" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="NID" code="569" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="Pre-emption-Control-Info" code="553" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Required-Access-Info" code="536" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="USER_LOCATION"/>
				<item code="1" name="MS_TIME_ZONE"/>
			</data>
		</avp>
		
		<avp name="Retry-Interval" code="541" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Rx-Request-Type" code="533" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="INITIAL_REQUEST"/>
				<item code="1" name="UPDATE_REQUEST"/>
				<item code="2" name="PCSCF_RESTORATION"/>
			</data>
		</avp>
		
		<avp name="Service-Authorization-Info" code="548" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Service-URN" code="525" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="Service-Info-Status" code="527" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="FINAL SERVICE INFORMATION"/>
				<item code="1" name="PRELIMINARY SERVICE INFORMATION"/>
			</data>
		</avp>
		
		<avp name="Specific-Action" code="513" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="Void"/>
				<item code="1" name="CHARGING_CORRELATION_EXCHANGE"/>
				<item code="2" name="INDICATION_OF_LOSS_OF_BEARER"/>
				<item code="3" name="INDICATION_OF_RECOVERY_OF_BEARER"/>
				<item code="4" name="INDICATION_OF_RELEASE_OF_BEARER"/>
				<item code="5" name="Void"/>
				<item code="6" name="IP-CAN_CHANGE"/>
				<item code="7" name="INDICATION_OF_OUT_OF_CREDIT"/>
				<item code="8" name="INDICATION_OF_SUCCESSFUL_RESOURCES_ALLOCATION"/>
				<item code="9" name="INDICATION_OF_FAILED_RESOURCES_ALLOCATION"/>
				<item code="10" name="INDICATION_OF_LIMITED_PCC_DEPLOYMENT"/>
				<item code="11" name="USAGE_REPORT"/>
				<item code="12" name="ACCESS_NETWORK_INFO_REPORT"/>
				<item code="13" name="INDICATION_OF_RECOVERY_FROM_LIMITED_PCC_DEPLOYMENT"/>
				<item code="14" name="INDICATION_OF_ACCESS_NETWORK_INFO_REPORTING_FAILURE"/>
				<item code="15" name="INDICATION_OF_TRANSFER_POLICY_EXPIRED"/>
				<item code="16" name="PLMN_CHANGE"/>
				<item code="17" name="EPS_FALLBACK"/>
				<item code="18" name="INDICATION_OF_REALLOCATION_OF_CREDIT"/>
			</data>
		</avp>
		
		<avp name="SIP-Forking-Indication" code="523" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="Enumerated">
				<item code="0" name="SINGLE_DIALOGUE"/>
				<item code="1" name="SEVERAL_DIALOGUES"/>
			</data>
		</avp>
		
		<avp name="Sponsored-Connectivity-Data" code="530" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="Sponsor-Identity" required="false" max="1"/>
				<rule avp="Application-Service-Provider-Identity" required="false" max="1"/>
				<rule avp="Granted-Service-Unit" required="false" max="1"/>
				<rule avp="Used-Service-Unit" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="Sponsor-Identity" code="531" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="UTF8String"/>
		</avp>
		
		<avp name="Application-Service-Provider-Identity" code="532" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="UTF8String"/>
		</avp>
		
		<avp name="Wireline-User-Location-Info" code="578" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Grouped">
				<rule avp="HFC-Node-Identifier" required="false" max="1"/>
				<rule avp="GLI-Identifier" required="false" max="1"/>
				<rule avp="Line-Type" required="false" max="1"/>
				<rule avp="AVP" required="false"/>
			</data>
		</avp>
		
		<avp name="HFC-Node-Identifier" code="579" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="GLI-Identifier" code="580" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="Line-Type" code="581" vendor-id="10415" must="V" may-encrypt="Y">
			<data type="Unsigned32"/>
		</avp>
		
		<avp name="Session-Id" code="263" must="M" may="P" must-not="V" may-encrypt="Y">
			<data type="UTF8String"/>
		</avp>
		
		 <avp name="Final-Unit-Action" code="449" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Enumerated">
                		<item code="0" name="TERMINATE"/>
                		<item code="1" name="REDIRECT"/>
                		<item code="2" name="RESTRICT_ACCESS"/>
            		</data>
        	</avp>

		 <avp name="Pre-emption-Capability" code="1047" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            		<data type="Enumerated">
                		<item code="0" name="PRE-EMPTION_CAPABILITY_ENABLED"/>
                		<item code="1" name="PRE-EMPTION_CAPABILITY_DISABLED"/>
            		</data>
        	</avp>

		<avp name="Pre-emption-Vulnerability" code="1048" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            		<data type="Enumerated">
                		<item code="0" name="PRE-EMPTION_VULNERABILITY_ENABLED"/>
                		<item code="1" name="PRE-EMPTION_VULNERABILITY_DISABLED"/>
            		</data>
        	</avp>

		<avp name="Reservation-Priority" code="458" vendor-id="10415" must="V" may-encrypt="Y">
            		<data type="Enumerated">
                		<item code="0" name="DEFAULT"/>
                		<item code="1" name="PRIORITY-ONE"/>
				<item code="2" name="PRIORITY-TWO"/>
                		<item code="3" name="PRIORITY-THREE"/>
				<item code="4" name="PRIORITY-FOUR"/>
                		<item code="5" name="PRIORITY-FIVE"/>
				<item code="6" name="PRIORITY-SIX"/>
                		<item code="7" name="PRIORITY-SEVEN"/>
            		</data>
        	</avp>
		
		<avp name="ToS-Traffic-Class" code="1014" vendor-id="10415" must="M,V" may-encrypt="Y">
			<data type="OctetString"/>
		</avp>
		
		<avp name="Called-Party-Address" code="832" must="V,M" may-encrypt="N" vendor-id="10415">
            		<data type="UTF8String"/>
        	</avp>

		<avp name="Requested-Party-Address" code="1251" must="V,M" may-encrypt="N" vendor-id="10415">
            		<data type="UTF8String"/>
        	</avp>

		 <avp name="Called-Asserted-Identity" code="1250" must="V,M" may-encrypt="N" vendor-id="10415">
        	    	<data type="UTF8String"/>
        	</avp>
		
		<avp name="IP-CAN-Type" code="1027" must="M,V" may-encrypt="Y" vendor-id="10415">
           		 <data type="Enumerated">
                		<item code="0" name="3GPP-GPRS"/>
                		<item code="1" name="DOCSIS"/>
                		<item code="2" name="xDSL"/>
                		<item code="3" name="WiMAX"/>
                		<item code="4" name="3GPP2"/>
                		<item code="5" name="3GPP-EPS"/>
                		<item code="6" name="Non-3GPP-EPS"/>
                		<item code="7" name="FBA"/>
                		<item code="8" name="3GPP-5GS"/>
                		<item code="9" name="Non-3GPP-5GS"/>
            		</data>
        	</avp>

		<avp name="RAT-Type" code="1032" must="M,V" may-encrypt="Y" vendor-id="10415">
            		<data type="Enumerated">
                		<item code="0" name="WLAN"/>
                		<item code="1" name="VIRTUAL"/>
				<item code="2" name="TRUSTED-N3GA"/>
				<item code="3" name="WIRELINE"/>
				<item code="4" name="WIRELINE-CABLE"/>
				<item code="5" name="WIRELINE-BBF"/>
                		<item code="1000" name="UTRAN"/>
                		<item code="1001" name="GERAN"/>
                		<item code="1002" name="GAN"/>
                		<item code="1003" name="HSPA_EVOLUTION"/>
                		<item code="1004" name="EUTRAN"/>
				<item code="1005" name="EUTRAN-NB-IoT"/>
				<item code="1006" name="NR"/>
				<item code="1007" name="LTE-M"/>
				<item code="1008" name="NR-U"/>
				<item code="1011" name="EUTRAN(LEO)"/>
				<item code="1012" name="EUTRAN(MEO)"/>
				<item code="1013" name="EUTRAN(GEO)"/>
				<item code="1014" name="EUTRAN(OTHERSAT)"/>
				<item code="1021" name="EUTRAN-NB-IoT(LEO)"/>
				<item code="1022" name="EUTRAN-NB-IoT(MEO)"/>
				<item code="1023" name="EUTRAN-NB-IoT(GEO)"/>
				<item code="1024" name="EUTRAN-NB-IoT(OTHERSAT)"/>
				<item code="1031" name="LTE-M(LEO)"/>
				<item code="1032" name="LTE-M(MEO)"/>
				<item code="1033" name="LTE-M(GEO)"/>
				<item code="1034" name="LTE-M(OTHERSAT)"/>
				<item code="1035" name="NR(LEO)"/>
				<item code="1036" name="NR(MEO)"/>
				<item code="1037" name="NR(GEO)"/>
				<item code="1038" name="NR(OTHERSAT)"/>
				<item code="1039" name="NR-REDCAP"/>
                		<item code="2000" name="CDMA2000_1X"/>
                		<item code="2001" name="HRPD"/>
                		<item code="2002" name="UMB"/>
                		<item code="2003" name="EHRPD"/>
            		</data>
        	</avp>

		<avp name="Granted-Service-Unit" code="431" must="M" may-encrypt="Y">
            		<data type="Grouped">
                		<rule avp="Tariff-Time-Change" required="false" max="1"/>
                		<rule avp="CC-Time" required="false" max="1"/>
                		<rule avp="CC-Money" required="false" max="1"/>
               	 		<rule avp="CC-Total-Octets" required="false" max="1"/>
                		<rule avp="CC-Input-Octets" required="false" max="1"/>
                		<rule avp="CC-Output-Octets" required="false" max="1"/>
                		<rule avp="CC-Service-Specific-Units" required="false" max="1"/>
                		<!-- *[ AVP ]-->
            		</data>
        	</avp>

		<avp name="Used-Service-Unit" code="446" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Grouped">
                		<rule avp="Tariff-Change-Usage" required="false" max="1"/>
                		<rule avp="CC-Time" required="false" max="1"/>
                		<rule avp="CC-Money" required="false" max="1"/>
                		<rule avp="CC-Total-Octets" required="false" max="1"/>
                		<rule avp="CC-Input-Octets" required="false" max="1"/>
                		<rule avp="CC-Output-Octets" required="false" max="1"/>
                		<rule avp="CC-Service-Specific-Units" required="false" max="1"/>
                		<!-- *[ AVP ]-->
            		</data>
        	</avp>
		
		 <avp name="Tariff-Time-Change" code="451" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Time"/>
        	</avp>

		<avp name="CC-Time" code="420" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Unsigned32"/>
        	</avp>

		 <avp name="CC-Money" code="413" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Grouped">
                		<rule avp="Unit-Value" required="true" max="1"/>
                		<rule avp="Currency-Code" required="true" max="1"/>
            		</data>
        	</avp>
	
		<avp name="Unit-Value" code="445" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Grouped">
                		<rule avp="Value-Digits" required="true" max="1"/>
                		<rule avp="Exponent" required="true" max="1"/>
            		</data>
        	</avp>

		<avp name="Currency-Code" code="425" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Unsigned32"/>
        	</avp>

		<avp name="Value-Digits" code="447" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Integer64"/>
        	</avp>

		<avp name="Exponent" code="429" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Integer32"/>
        	</avp>

		<avp name="CC-Total-Octets" code="421" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Unsigned64"/>
        	</avp>

		 <avp name="CC-Output-Octets" code="414" must="M" may="P" must-not="V" may-encrypt="Y">
        	    	<data type="Unsigned64"/>
        	</avp>

		 <avp name="CC-Service-Specific-Units" code="417" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Unsigned64"/>
        	</avp>
		
        	<avp name="CC-Input-Octets" code="412" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Unsigned64"/>
        	</avp>

		<avp name="DRMP" code="301" must-not="V">
            		<data type="Enumerated">
                		<item code="0" name="PRIORITY_0"/>
                		<item code="1" name="PRIORITY_1"/>
                		<item code="2" name="PRIORITY_2"/>
                		<item code="3" name="PRIORITY_3"/>
                		<item code="4" name="PRIORITY_4"/>
                		<item code="5" name="PRIORITY_5"/>
                		<item code="6" name="PRIORITY_6"/>
                		<item code="7" name="PRIORITY_7"/>
                		<item code="8" name="PRIORITY_8"/>
                		<item code="9" name="PRIORITY_9"/>
                		<item code="10" name="PRIORITY_10"/>
                		<item code="11" name="PRIORITY_11"/>
                		<item code="12" name="PRIORITY_12"/>
                		<item code="13" name="PRIORITY_13"/>
                		<item code="14" name="PRIORITY_14"/>
                		<item code="15" name="PRIORITY_15"/>
            		</data>
        	</avp>

		<avp name="Origin-Host" code="264" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="DiameterIdentity"/>
        	</avp>

		<avp name="Origin-Realm" code="296" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="DiameterIdentity"/>
        	</avp>

		<avp name="Destination-Host" code="293" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="DiameterIdentity"/>
        	</avp>

        	<avp name="Destination-Realm" code="283" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="DiameterIdentity"/>
        	</avp>
		
		<avp name="Auth-Application-Id" code="258" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Unsigned32"/>
        	</avp>

		<avp name="Auth-Session-State" code="277" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Enumerated">
                		<item code="0" name="STATE_MAINTAINED"/>
                		<item code="1" name="NO_STATE_MAINTAINED"/>
            		</data>
        	</avp>

		 <avp name="Subscription-Id" code="443" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Grouped">
                		<rule avp="Subscription-Id-Type" required="true" max="1"/>
                		<rule avp="Subscription-Id-Data" required="true" max="1"/>
            		</data>
        	</avp>

        	<avp name="Subscription-Id-Data" code="444" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="UTF8String"/>
        	</avp>

        	<avp name="Subscription-Id-Type" code="450" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="Enumerated">
                		<item code="0" name="END_USER_E164"/>
                		<item code="1" name="END_USER_IMSI"/>
                		<item code="2" name="END_USER_SIP_URI"/>
                		<item code="3" name="END_USER_NAI"/>
            		</data>
        	</avp>

		<avp name="OC-Supported-Features" code="621" must-not="V">
            		<data type="Grouped">
                		<rule avp="Subscription-Id-Type" required="true" max="1"/>
                		<rule avp="Subscription-Id-Data" required="true" max="1"/>
            		</data>
        	</avp>
		
		<avp name="Supported-Features" code="628" vendor-id="10415" must="V" may="M" may-encrypt="N">
			<data type="Grouped">
				<rule avp="Vendor-Id" required="true" max="1"/>
				<rule avp="Feature-List-ID" required="true" max="1"/>
				<rule avp="Feature-List" required="true" max="1"/>
			</data>
		</avp>
		
		<avp name="Vendor-Id" code="266" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Unsigned32"/>
        	</avp>
	
		<avp name="Feature-List-ID" code="629" must="V" must_not="M" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Feature-List" code="630" must="V" must-not="M" may-encrypt="N" vendor-id="10415">
			<data type="Unsigned32"/>
		</avp>

		<avp name="Framed-IP-Address" code="8" must="M" may="-" must-not="V" may-encrypt="Y">
            		<data type="OctetString"/>
        	</avp>
		
		<avp name="Called-Station-Id" code="30" must="M" may="-" must-not="V" may-encrypt="Y">
            		<data type="UTF8String"/>
        	</avp>
	
		<avp name="IMS-Content-Identifier" code="563" must="V" may-encrypt="Y">
            		<data type="OctetString"/>
        	</avp>
		
		<avp name="IMS-Content-Type" code="564" must="V" may-encrypt="Y">
            		<data type="Enumerated">
				<item code="0" name="NO_CONTENT_DETAIL"/>
                		<item code="1" name="CAT"/>
                		<item code="2" name="CONFERENCE"/>
			</data>
        	</avp>
		
		<avp name="Calling-Party-Address" code="831" must="V,M" may="P" must-not="-" may-encrypt="N" vendor-id="10415">
            		<data type="UTF8String"/>
        	</avp>
		
		<avp name="Reference-Id" code="4202" must="M,V" vendor-id="10415">
            		<data type="OctetString"/>
        	</avp>
		
		 <avp name="Origin-State-Id" code="278" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Unsigned32"/>
        	</avp>		
		
		<avp name="Proxy-Info" code="284" must="M" may="-" must-not="P,V" may-encrypt="-">
            		<data type="Grouped">
                		<rule avp="Proxy-Host" required="true" max="1"/>
                		<rule avp="Proxy-State" required="true" max="1"/>
            		</data>
        	</avp>
		
		<avp name="Proxy-Host" code="280" must="M" may="-" must-not="P,V" may-encrypt="-">
            		<data type="DiameterIdentity"/>
        	</avp>

        	<avp name="Proxy-State" code="33" must="M" may="-" must-not="P,V" may-encrypt="-">
            		<data type="OctetString"/>
        	</avp>

		 <avp name="Route-Record" code="282" must="M" may="-" must-not="P,V" may-encrypt="-">
            		<data type="DiameterIdentity"/>
        	</avp>

		 <avp name="Result-Code" code="268" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Unsigned32"/>
        	</avp>

		 <avp name="Experimental-Result" code="297" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Grouped">
                		<rule avp="Vendor-Id" required="true" max="1"/>
                		<rule avp="Experimental-Result-Code" required="true" max="1"/>
            		</data>
        	</avp>

        	<avp name="Experimental-Result-Code" code="298" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Unsigned32"/>
        	</avp>
		
		 <avp name="AN-GW-Address" code="1050" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            		<data type="Address"/>
        	</avp>

		<avp name="AN-Trusted" code="1503" must="M,V">
            		<data type="Enumerated">
				<item code="0" name="TRUSTED"/>
                		<item code="1" name="UNTRUSTED"/>
			</data>
        	</avp>

		<avp name="NetLoc-Access-Support" code="2824" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            		<data type="Unsigned32"/>
        	</avp>
		
		<avp name="OC-OLR" code="623" must-not="M,V">
            		<data type="Grouped">
                		<rule avp="OC-Sequence-Number" required="true" max="1"/>
                		<rule avp="OC-Report-Type" required="true" max="1"/>
                		<rule avp="OC-Reduction-Percentage" required="false" max="1"/>
                		<rule avp="OC-Validity-Duration" required="false" max="1"/>
                		<rule avp="AVP" required="false"/>
            		</data>
        	</avp>

        	<avp name="OC-Sequence-Number" code="624" must-not="V">
           		<data type="Unsigned64"/>
        	</avp>

       	 	<avp name="OC-Validity-Duration" code="625" must-not="V">
            		<data type="Unsigned32"/>
        	</avp>

        	<avp name="OC-Report-Type" code="626" must-not="V">
            		<data type="Enumerated">
                		<item code="0" name="HOST_REPORT"/>
                		<item code="1" name="REALM_REPORT"/>
            		</data>
        	</avp>

        	<avp name="OC-Reduction-Percentage" code="627" must-not="V">
            		<data type="Unsigned32"/>
        	</avp>
		
		<avp name="User-Equipment-Info" code="458" must="-" may="P,M" must-not="V" may-encrypt="Y">
            		<data type="Grouped">
                		<rule avp="User-Equipment-Info-Type" required="true" max="1"/>
                		<rule avp="User-Equipment-Info-Value" required="true" max="1"/>
            		</data>
        	</avp>

        	<avp name="User-Equipment-Info-Type" code="459" must="-" may="P,M" must-not="V" may-encrypt="Y">
            		<data type="Enumerated">
                		<item code="0" name="IMEISV"/>
                		<item code="1" name="MAC"/>
                		<item code="2" name="EUI64"/>
                		<item code="3" name="MODIFIED_EUI64"/>
            		</data>
        	</avp>

        	<avp name="User-Equipment-Info-Value" code="460" must="-" may="P,M" must-not="V" may-encrypt="Y">
            		<data type="OctetString"/>
        	</avp>

		<avp name="Class" code="25" must="M" may="P" must-not="V" may-encrypt="Y">
            		<data type="OctetString"/>
        	</avp>
		
		 <avp name="Error-Message" code="281" must="-" may="P" must-not="V,M" may-encrypt="-">
            		<data type="UTF8String"/>
        	</avp>

        	<avp name="Error-Reporting-Host" code="294" must="-" may="P" must-not="V,M" may-encrypt="-">
            		<data type="DiameterIdentity"/>
        	</avp>

		 <avp name="Redirect-Host" code="292" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="DiameterURI"/>
        	</avp>
		
		 <avp name="Redirect-Host-Usage" code="261" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Enumerated">
                		<item code="0" name="DONT_CACHE"/>
                		<item code="1" name="ALL_SESSION"/>
                		<item code="2" name="ALL_REALM"/>
                		<item code="3" name="REALM_AND_APPLICATION"/>
               		 	<item code="4" name="ALL_APPLICATION"/>
                		<item code="5" name="ALL_HOST"/>
                		<item code="6" name="ALL_USER"/>
            		</data>
        	</avp>
		
		<avp name="Redirect-Max-Cache-Time" code="262" must="M" may="P" must-not="V" may-encrypt="-">
            		<data type="Unsigned32"/>
        	</avp>

		<avp name="User-Location-Info-Time" code="2812" must="V" may="P" must-not="M" may-encrypt="Y">
        	    	<data type="Time"/>
	        </avp>

		<avp name="RAN-NAS-Release-Cause" code="2819" must="V" may="P" must-not="M" may-encrypt="Y">
        	    	<data type="OctetString"/>
	        </avp>

		<avp name="TWAN-Identifier" code="29" must="V" may="P" must-not="M" may-encrypt="Y">
        	    	<data type="OctetString"/>
	        </avp>


		<avp name="TCP-Source-Port" code="2843" must="V" may="P" must-not="M" may-encrypt="Y">
        	    	<data type="Unsigned32"/>
	        </avp>


		<avp name="UDP-Source-Port" code="2806" must="V" may="P" must-not="M" may-encrypt="Y">
        	    	<data type="Unsigned32"/>
	        </avp>


		<avp name="UE-Local-IP-Address" code="2805" must="V" may="P" must-not="M" may-encrypt="Y">
        	    	<data type="Address"/>
	        </avp>

		<avp name="Failed-AVP" code="279" must="M" may="P" must-not="V" may-encrypt="-">
        	    	<data type="Grouped"/>
	        </avp>

		<avp name="Framed-Ipv6-Prefix" code="97" must="M" may-encrypt="Y">
            		<data type="OctetString"/>
	        </avp>
	
		<avp name="TGPP-SGSN-MCC-MNC" code="18" must="V"    may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            		<data type="UTF8String"/>
        	</avp>

        	<avp name="TGPP-User-Location-Info" code="22" must="V"  may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            		<data type="OctetString"/>
	        </avp>

   		<avp name="TGPP-MS-TimeZone" code="23" must="V" may="P" must-not="M" may-encrypt="Y" vendor-id="10415">
            		<data type="OctetString"/>
       </avp>
	</application>
</diameter>`
