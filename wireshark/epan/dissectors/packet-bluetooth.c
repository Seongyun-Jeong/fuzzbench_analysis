/* packet-bluetooth.c
 * Routines for the Bluetooth
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Dissector for Bluetooth High Speed over wireless
 * Copyright 2012 intel Corp.
 * Written by Andrei Emeltchenko at intel dot com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/conversation_table.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <wiretap/wtap.h>
#include "packet-llc.h"
#include <epan/oui.h>

#include "packet-bluetooth.h"

int proto_bluetooth = -1;

static int hf_bluetooth_src = -1;
static int hf_bluetooth_dst = -1;
static int hf_bluetooth_addr = -1;
static int hf_bluetooth_src_str = -1;
static int hf_bluetooth_dst_str = -1;
static int hf_bluetooth_addr_str = -1;

static int hf_llc_bluetooth_pid = -1;

static gint ett_bluetooth = -1;

static dissector_handle_t btle_handle;
static dissector_handle_t hci_usb_handle;

static dissector_table_t bluetooth_table;
static dissector_table_t hci_vendor_table;
dissector_table_t        bluetooth_uuid_table;

static wmem_tree_t *chandle_sessions        = NULL;
static wmem_tree_t *chandle_to_bdaddr       = NULL;
static wmem_tree_t *chandle_to_mode         = NULL;
static wmem_tree_t *shandle_to_chandle      = NULL;
static wmem_tree_t *bdaddr_to_name          = NULL;
static wmem_tree_t *bdaddr_to_role          = NULL;
static wmem_tree_t *localhost_name          = NULL;
static wmem_tree_t *localhost_bdaddr        = NULL;
static wmem_tree_t *hci_vendors             = NULL;

wmem_tree_t *bluetooth_uuids = NULL;

static int bluetooth_tap = -1;
int bluetooth_device_tap = -1;
int bluetooth_hci_summary_tap = -1;

const value_string bluetooth_uuid_vals[] = {
    /* Protocol Identifiers - https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/ */
    { 0x0001,   "SDP" },
    { 0x0002,   "UDP" },
    { 0x0003,   "RFCOMM" },
    { 0x0004,   "TCP" },
    { 0x0005,   "TCS-BIN" },
    { 0x0006,   "TCS-AT" },
    { 0x0007,   "ATT" },
    { 0x0008,   "OBEX" },
    { 0x0009,   "IP" },
    { 0x000A,   "FTP" },
    { 0x000C,   "HTTP" },
    { 0x000E,   "WSP" },
    { 0x000F,   "BNEP" },
    { 0x0010,   "UPNP" },
    { 0x0011,   "HIDP" },
    { 0x0012,   "Hardcopy Control Channel" },
    { 0x0014,   "Hardcopy Data Channel" },
    { 0x0016,   "Hardcopy Notification" },
    { 0x0017,   "AVCTP" },
    { 0x0019,   "AVDTP" },
    { 0x001B,   "CMPT" },
    { 0x001D,   "UDI C-Plane" }, /* unofficial */
    { 0x001E,   "MCAP Control Channel" },
    { 0x001F,   "MCAP Data Channel" },
    { 0x0100,   "L2CAP" },
    /* Traditional Services - https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/ */
    { 0x1000,   "Service Discovery Server Service Class ID" },
    { 0x1001,   "Browse Group Descriptor Service Class ID" },
    { 0x1002,   "Public Browse Group" },
    { 0x1101,   "Serial Port" },
    { 0x1102,   "LAN Access Using PPP" },
    { 0x1103,   "Dialup Networking" },
    { 0x1104,   "IrMC Sync" },
    { 0x1105,   "OBEX Object Push" },
    { 0x1106,   "OBEX File Transfer" },
    { 0x1107,   "IrMC Sync Command" },
    { 0x1108,   "Headset" },
    { 0x1109,   "Cordless Telephony" },
    { 0x110A,   "Audio Source" },
    { 0x110B,   "Audio Sink" },
    { 0x110C,   "A/V Remote Control Target" },
    { 0x110D,   "Advanced Audio Distribution" },
    { 0x110E,   "A/V Remote Control" },
    { 0x110F,   "A/V Remote Control Controller" },
    { 0x1110,   "Intercom" },
    { 0x1111,   "Fax" },
    { 0x1112,   "Headset Audio Gateway" },
    { 0x1113,   "WAP" },
    { 0x1114,   "WAP Client" },
    { 0x1115,   "PAN PANU" },
    { 0x1116,   "PAN NAP" },
    { 0x1117,   "PAN GN" },
    { 0x1118,   "Direct Printing" },
    { 0x1119,   "Reference Printing" },
    { 0x111A,   "Imaging" },
    { 0x111B,   "Imaging Responder" },
    { 0x111C,   "Imaging Automatic Archive" },
    { 0x111D,   "Imaging Referenced Objects" },
    { 0x111E,   "Handsfree" },
    { 0x111F,   "Handsfree Audio Gateway" },
    { 0x1120,   "Direct Printing Reference Objects Service" },
    { 0x1121,   "Reflected UI" },
    { 0x1122,   "Basic Printing" },
    { 0x1123,   "Printing Status" },
    { 0x1124,   "Human Interface Device Service" },
    { 0x1125,   "Hardcopy Cable Replacement" },
    { 0x1126,   "HCR Print" },
    { 0x1127,   "HCR Scan" },
    { 0x1128,   "Common ISDN Access" },
    { 0x1129,   "Video Conferencing GW" },
    { 0x112A,   "UDI MT" },
    { 0x112B,   "UDI TA" },
    { 0x112C,   "Audio/Video" },
    { 0x112D,   "SIM Access" },
    { 0x112E,   "Phonebook Access Client" },
    { 0x112F,   "Phonebook Access Server" },
    { 0x1130,   "Phonebook Access Profile" },
    { 0x1131,   "Headset HS" },
    { 0x1132,   "Message Access Server" },
    { 0x1133,   "Message Notification Server" },
    { 0x1134,   "Message Access Profile" },
    { 0x1135,   "Global Navigation Satellite System" },
    { 0x1136,   "Global Navigation Satellite System Server" },
    { 0x1137,   "3D Display" },
    { 0x1138,   "3D Glasses" },
    { 0x1139,   "3D Synchronization Profile" },
    { 0x113A,   "Multi-Profile" },
    { 0x113B,   "Multi-Profile SC" },
    { 0x113C,   "Calendar, Task and Notes Access Service" },
    { 0x113D,   "Calendar, Task and Notes Notification Service" },
    { 0x113E,   "Calendar, Task and Notes Profile" },
    { 0x1200,   "PnP Information" },
    { 0x1201,   "Generic Networking" },
    { 0x1202,   "Generic File Transfer" },
    { 0x1203,   "Generic Audio" },
    { 0x1204,   "Generic Telephony" },
    { 0x1205,   "UPNP Service" },
    { 0x1206,   "UPNP IP Service" },
    { 0x1300,   "ESDP UPNP_IP PAN" },
    { 0x1301,   "ESDP UPNP IP LAP" },
    { 0x1302,   "ESDP UPNP L2CAP" },
    { 0x1303,   "Video Source" },
    { 0x1304,   "Video Sink" },
    { 0x1305,   "Video Distribution" },
    { 0x1400,   "Health Device Profile" },
    { 0x1401,   "Health Device Source" },
    { 0x1402,   "Health Device Sink" },
    /* LE Services -  https://www.bluetooth.com/specifications/gatt/services */
    { 0x1800,   "Generic Access Profile" },
    { 0x1801,   "Generic Attribute Profile" },
    { 0x1802,   "Immediate Alert" },
    { 0x1803,   "Link Loss" },
    { 0x1804,   "Tx Power" },
    { 0x1805,   "Current Time Service" },
    { 0x1806,   "Reference Time Update Service" },
    { 0x1807,   "Next DST Change Service" },
    { 0x1808,   "Glucose" },
    { 0x1809,   "Health Thermometer" },
    { 0x180A,   "Device Information" },
    { 0x180D,   "Heart Rate" },
    { 0x180E,   "Phone Alert Status Service" },
    { 0x180F,   "Battery Service" },
    { 0x1810,   "Blood Pressure" },
    { 0x1811,   "Alert Notification Service" },
    { 0x1812,   "Human Interface Device" },
    { 0x1813,   "Scan Parameters" },
    { 0x1814,   "Running Speed and Cadence" },
    { 0x1815,   "Automation IO" },
    { 0x1816,   "Cycling Speed and Cadence" },
    { 0x1818,   "Cycling Power" },
    { 0x1819,   "Location and Navigation" },
    { 0x181A,   "Environmental Sensing" },
    { 0x181B,   "Body Composition" },
    { 0x181C,   "User Data" },
    { 0x181D,   "Weight Scale" },
    { 0x181E,   "Bond Management" },
    { 0x181F,   "Continuous Glucose Monitoring" },
    { 0x1820,   "Internet Protocol Support" },
    { 0x1821,   "Indoor Positioning" },
    { 0x1822,   "Pulse Oximeter" },
    { 0x1823,   "HTTP Proxy" },
    { 0x1824,   "Transport Discovery" },
    { 0x1825,   "Object Transfer" },
    { 0x1826,   "Fitness Machine" },
    { 0x1827,   "Mesh Provisioning Service" },
    { 0x1828,   "Mesh Proxy Service" },
    { 0x1829,   "Reconnection Configuration" },
    { 0x183A,   "Insulin Delivery" },
    { 0x183B,   "Binary Sensor" },
    { 0x183C,   "Emergency Configuration" },
    { 0x183E,   "Physical Activity Monitor" },
    { 0x1843,   "Audio Input Control" },
    { 0x1844,   "Volume Control" },
    { 0x1845,   "Volume Offset Control" },
    { 0x1846,   "Coordinated Set Identification Service" },
    { 0x1847,   "Device Time" },
    { 0x1848,   "Media Control Service" },
    { 0x1849,   "Generic Media Control Service" },
    { 0x184A,   "Constant Tone Extension" },
    { 0x184B,   "Telephone Bearer Service" },
    { 0x184C,   "Generic Telephone Bearer Service" },
    { 0x184D,   "Microphone Control" },
    { 0x184E,   "Audio Stream Control Service" },
    { 0x184F,   "Broadcast Audio Scan Service " },
    { 0x1850,   "Published Audio Capabilities Service" },
    { 0x1851,   "Basic Audio Announcement Service" },
    { 0x1852,   "Broadcast Audio Announcement Service" },
    /* Units - https://www.bluetooth.com/specifications/assigned-numbers/units */
    { 0x2700,   "unitless" },
    { 0x2701,   "length (metre)" },
    { 0x2702,   "mass (kilogram)" },
    { 0x2703,   "time (second)" },
    { 0x2704,   "electric current (ampere)" },
    { 0x2705,   "thermodynamic temperature (kelvin)" },
    { 0x2706,   "amount of substance (mole)" },
    { 0x2707,   "luminous intensity (candela)" },
    { 0x2710,   "area (square metres)" },
    { 0x2711,   "volume (cubic metres)" },
    { 0x2712,   "velocity (metres per second)" },
    { 0x2713,   "acceleration (metres per second squared)" },
    { 0x2714,   "wavenumber (reciprocal metre)" },
    { 0x2715,   "density (kilogram per cubic metre)" },
    { 0x2716,   "surface density (kilogram per square metre)" },
    { 0x2717,   "specific volume (cubic metre per kilogram)" },
    { 0x2718,   "current density (ampere per square metre)" },
    { 0x2719,   "magnetic field strength (ampere per metre)" },
    { 0x271A,   "amount concentration (mole per cubic metre)" },
    { 0x271B,   "mass concentration (kilogram per cubic metre)" },
    { 0x271C,   "luminance (candela per square metre)" },
    { 0x271D,   "refractive index" },
    { 0x271E,   "relative permeability" },
    { 0x2720,   "plane angle (radian)" },
    { 0x2721,   "solid angle (steradian)" },
    { 0x2722,   "frequency (hertz)" },
    { 0x2723,   "force (newton)" },
    { 0x2724,   "pressure (pascal)" },
    { 0x2725,   "energy (joule)" },
    { 0x2726,   "power (watt)" },
    { 0x2727,   "electric charge (coulomb)" },
    { 0x2728,   "electric potential difference (volt)" },
    { 0x2729,   "capacitance (farad)" },
    { 0x272A,   "electric resistance (ohm)" },
    { 0x272B,   "electric conductance (siemens)" },
    { 0x272C,   "magnetic flux (weber)" },
    { 0x272D,   "magnetic flux density (tesla)" },
    { 0x272E,   "inductance (henry)" },
    { 0x272F,   "Celsius temperature (degree Celsius)" },
    { 0x2730,   "luminous flux (lumen)" },
    { 0x2731,   "illuminance (lux)" },
    { 0x2732,   "activity referred to a radionuclide (becquerel)" },
    { 0x2733,   "absorbed dose (gray)" },
    { 0x2734,   "dose equivalent (sievert)" },
    { 0x2735,   "catalytic activity (katal)" },
    { 0x2740,   "dynamic viscosity (pascal second)" },
    { 0x2741,   "moment of force (newton metre)" },
    { 0x2742,   "surface tension (newton per metre)" },
    { 0x2743,   "angular velocity (radian per second)" },
    { 0x2744,   "angular acceleration (radian per second squared)" },
    { 0x2745,   "heat flux density (watt per square metre)" },
    { 0x2746,   "heat capacity (joule per kelvin)" },
    { 0x2747,   "specific heat capacity (joule per kilogram kelvin)" },
    { 0x2748,   "specific energy (joule per kilogram)" },
    { 0x2749,   "thermal conductivity (watt per metre kelvin)" },
    { 0x274A,   "energy density (joule per cubic metre)" },
    { 0x274B,   "electric field strength (volt per metre)" },
    { 0x274C,   "electric charge density (coulomb per cubic metre)" },
    { 0x274D,   "surface charge density (coulomb per square metre)" },
    { 0x274E,   "electric flux density (coulomb per square metre)" },
    { 0x274F,   "permittivity (farad per metre)" },
    { 0x2750,   "permeability (henry per metre)" },
    { 0x2751,   "molar energy (joule per mole)" },
    { 0x2752,   "molar entropy (joule per mole kelvin)" },
    { 0x2753,   "exposure (coulomb per kilogram)" },
    { 0x2754,   "absorbed dose rate (gray per second)" },
    { 0x2755,   "radiant intensity (watt per steradian)" },
    { 0x2756,   "radiance (watt per square metre steradian)" },
    { 0x2757,   "catalytic activity concentration (katal per cubic metre)" },
    { 0x2760,   "time (minute)" },
    { 0x2761,   "time (hour)" },
    { 0x2762,   "time (day)" },
    { 0x2763,   "plane angle (degree)" },
    { 0x2764,   "plane angle (minute)" },
    { 0x2765,   "plane angle (second)" },
    { 0x2766,   "area (hectare)" },
    { 0x2767,   "volume (litre)" },
    { 0x2768,   "mass (tonne)" },
    { 0x2780,   "pressure (bar)" },
    { 0x2781,   "pressure (millimetre of mercury)" },
    { 0x2782,   "length (angstrom)" },  /* Bluetooth changes this to "ngstrm", mistake? */
    { 0x2783,   "length (nautical mile)" },
    { 0x2784,   "area (barn)" },
    { 0x2785,   "velocity (knot)" },
    { 0x2786,   "logarithmic radio quantity (neper)" },
    { 0x2787,   "logarithmic radio quantity (bel)" },
    { 0x27A0,   "length (yard)" },
    { 0x27A1,   "length (parsec)" },
    { 0x27A2,   "length (inch)" },
    { 0x27A3,   "length (foot)" },
    { 0x27A4,   "length (mile)" },
    { 0x27A5,   "pressure (pound-force per square inch)" },
    { 0x27A6,   "velocity (kilometre per hour)" },
    { 0x27A7,   "velocity (mile per hour)" },
    { 0x27A8,   "angular velocity (revolution per minute)" },
    { 0x27A9,   "energy (gram calorie)" },
    { 0x27AA,   "energy (kilogram calorie)" },
    { 0x27AB,   "energy (kilowatt hour)" },
    { 0x27AC,   "thermodynamic temperature (degree Fahrenheit)" },
    { 0x27AD,   "percentage" },
    { 0x27AE,   "per mille" },
    { 0x27AF,   "period (beats per minute)" },
    { 0x27B0,   "electric charge (ampere hours)" },
    { 0x27B1,   "mass density (milligram per decilitre)" },
    { 0x27B2,   "mass density (millimole per litre)" },
    { 0x27B3,   "time (year)" },
    { 0x27B4,   "time (month)" },
    { 0x27B5,   "concentration (count per cubic metre)" },
    { 0x27B6,   "irradiance (watt per square metre)" },
    { 0x27B7,   "milliliter (per kilogram per minute)" },
    { 0x27B8,   "mass (pound)" },
    { 0x27B9,   "metabolic equivalent" },
    { 0x27BA,   "step (per minute)" },
    { 0x27BC,   "stroke (per minute)" },
    { 0x27BD,   "pace (kilometre per minute)" },
    { 0x27BE,   "luminous efficacy (lumen per watt)" },
    { 0x27BF,   "luminous energy (lumen hour)" },
    { 0x27C0,   "luminous exposure (lux hour)" },
    { 0x27C1,   "mass flow (gram per second)" },
    { 0x27C2,   "volume flow (litre per second)" },
    { 0x27C3,   "sound pressure (decibel)" },
    { 0x27C4,   "concentration (parts per million)" },
    { 0x27C5,   "concentration (parts per billion)" },
    /* Declarations - https://www.bluetooth.com/specifications/gatt/declarations */
    { 0x2800,   "GATT Primary Service Declaration" },
    { 0x2801,   "GATT Secondary Service Declaration" },
    { 0x2802,   "GATT Include Declaration" },
    { 0x2803,   "GATT Characteristic Declaration" },
    /* Descriptors - https://www.bluetooth.com/specifications/gatt/descriptors */
    { 0x2900,   "Characteristic Extended Properties" },
    { 0x2901,   "Characteristic User Description" },
    { 0x2902,   "Client Characteristic Configuration" },
    { 0x2903,   "Server Characteristic Configuration" },
    { 0x2904,   "Characteristic Presentation Format" },
    { 0x2905,   "Characteristic Aggregate Format" },
    { 0x2906,   "Valid Range" },
    { 0x2907,   "External Report Reference" },
    { 0x2908,   "Report Reference" },
    { 0x2909,   "Number of Digitals" },
    { 0x290A,   "Value Trigger Setting" },
    { 0x290B,   "Environmental Sensing Configuration" },
    { 0x290C,   "Environmental Sensing Measurement" },
    { 0x290D,   "Environmental Sensing Trigger Setting" },
    { 0x290E,   "Time Trigger Setting" },
    /* Characteristics - https://www.bluetooth.com/specifications/gatt/characteristics */
    { 0x2A00,   "Device Name" },
    { 0x2A01,   "Appearance" },
    { 0x2A02,   "Peripheral Privacy Flag" },
    { 0x2A03,   "Reconnection Address" },
    { 0x2A04,   "Peripheral Preferred Connection Parameters" },
    { 0x2A05,   "Service Changed" },
    { 0x2A06,   "Alert Level" },
    { 0x2A07,   "Tx Power Level" },
    { 0x2A08,   "Date Time" },
    { 0x2A09,   "Day of Week" },
    { 0x2A0A,   "Day Date Time" },
    { 0x2A0B,   "Exact Time 100" },
    { 0x2A0C,   "Exact Time 256" },
    { 0x2A0D,   "DST Offset" },
    { 0x2A0E,   "Time Zone" },
    { 0x2A0F,   "Local Time Information" },
    { 0x2A10,   "Secondary Time Zone" },
    { 0x2A11,   "Time with DST" },
    { 0x2A12,   "Time Accuracy" },
    { 0x2A13,   "Time Source" },
    { 0x2A14,   "Reference Time Information" },
    { 0x2A15,   "Time Broadcast" },
    { 0x2A16,   "Time Update Control Point" },
    { 0x2A17,   "Time Update State" },
    { 0x2A18,   "Glucose Measurement" },
    { 0x2A19,   "Battery Level" },
    { 0x2A1A,   "Battery Power State" },
    { 0x2A1B,   "Battery Level State" },
    { 0x2A1C,   "Temperature Measurement" },
    { 0x2A1D,   "Temperature Type" },
    { 0x2A1E,   "Intermediate Temperature" },
    { 0x2A1F,   "Temperature Celsius" },
    { 0x2A20,   "Temperature Fahrenheit" },
    { 0x2A21,   "Measurement Interval" },
    { 0x2A22,   "Boot Keyboard Input Report" },
    { 0x2A23,   "System ID" },
    { 0x2A24,   "Model Number String" },
    { 0x2A25,   "Serial Number String" },
    { 0x2A26,   "Firmware Revision String" },
    { 0x2A27,   "Hardware Revision String" },
    { 0x2A28,   "Software Revision String" },
    { 0x2A29,   "Manufacturer Name String" },
    { 0x2A2A,   "IEEE 11073-20601 Regulatory Certification Data List" },
    { 0x2A2B,   "Current Time" },
    { 0x2A2C,   "Magnetic Declination" },
    { 0x2A2F,   "Position 2D" },
    { 0x2A30,   "Position 3D" },
    { 0x2A31,   "Scan Refresh" },
    { 0x2A32,   "Boot Keyboard Output Report" },
    { 0x2A33,   "Boot Mouse Input Report" },
    { 0x2A34,   "Glucose Measurement Context" },
    { 0x2A35,   "Blood Pressure Measurement" },
    { 0x2A36,   "Intermediate Cuff Pressure" },
    { 0x2A37,   "Heart Rate Measurement" },
    { 0x2A38,   "Body Sensor Location" },
    { 0x2A39,   "Heart Rate Control Point" },
    { 0x2A3A,   "Removable" },
    { 0x2A3B,   "Service Required" },
    { 0x2A3C,   "Scientific Temperature Celsius" },
    { 0x2A3D,   "String" },
    { 0x2A3E,   "Network Availability" },
    { 0x2A3F,   "Alert Status" },
    { 0x2A40,   "Ringer Control Point" },
    { 0x2A41,   "Ringer Setting" },
    { 0x2A42,   "Alert Category ID Bit Mask" },
    { 0x2A43,   "Alert Category ID" },
    { 0x2A44,   "Alert Notification Control Point" },
    { 0x2A45,   "Unread Alert Status" },
    { 0x2A46,   "New Alert" },
    { 0x2A47,   "Supported New Alert Category" },
    { 0x2A48,   "Supported Unread Alert Category" },
    { 0x2A49,   "Blood Pressure Feature" },
    { 0x2A4A,   "HID Information" },
    { 0x2A4B,   "Report Map" },
    { 0x2A4C,   "HID Control Point" },
    { 0x2A4D,   "Report" },
    { 0x2A4E,   "Protocol Mode" },
    { 0x2A4F,   "Scan Interval Window" },
    { 0x2A50,   "PnP ID" },
    { 0x2A51,   "Glucose Feature" },
    { 0x2A52,   "Record Access Control Point" },
    { 0x2A53,   "RSC Measurement" },
    { 0x2A54,   "RSC Feature" },
    { 0x2A55,   "SC Control Point" },
    { 0x2A56,   "Digital" },
    { 0x2A57,   "Digital Output" },
    { 0x2A58,   "Analog" },
    { 0x2A59,   "Analog Output" },
    { 0x2A5A,   "Aggregate" },
    { 0x2A5B,   "CSC Measurement" },
    { 0x2A5C,   "CSC Feature" },
    { 0x2A5D,   "Sensor Location" },
    { 0x2A5E,   "PLX Spot-Check Measurement" },
    { 0x2A5F,   "PLX Continuous Measurement" },
    { 0x2A60,   "PLX Features" },
    { 0x2A62,   "Pulse Oximetry Control Point" },
    { 0x2A63,   "Cycling Power Measurement" },
    { 0x2A64,   "Cycling Power Vector" },
    { 0x2A65,   "Cycling Power Feature" },
    { 0x2A66,   "Cycling Power Control Point" },
    { 0x2A67,   "Location and Speed" },
    { 0x2A68,   "Navigation" },
    { 0x2A69,   "Position Quality" },
    { 0x2A6A,   "LN Feature" },
    { 0x2A6B,   "LN Control Point" },
    { 0x2A6C,   "Elevation" },
    { 0x2A6D,   "Pressure" },
    { 0x2A6E,   "Temperature" },
    { 0x2A6F,   "Humidity" },
    { 0x2A70,   "True Wind Speed" },
    { 0x2A71,   "True Wind Direction" },
    { 0x2A72,   "Apparent Wind Speed" },
    { 0x2A73,   "Apparent Wind Direction" },
    { 0x2A74,   "Gust Factor" },
    { 0x2A75,   "Pollen Concentration" },
    { 0x2A76,   "UV Index" },
    { 0x2A77,   "Irradiance" },
    { 0x2A78,   "Rainfall" },
    { 0x2A79,   "Wind Chill" },
    { 0x2A7A,   "Heat Index" },
    { 0x2A7B,   "Dew Point" },
    { 0x2A7D,   "Descriptor Value Changed" },
    { 0x2A7E,   "Aerobic Heart Rate Lower Limit" },
    { 0x2A7F,   "Aerobic Threshold" },
    { 0x2A80,   "Age" },
    { 0x2A81,   "Anaerobic Heart Rate Lower Limit" },
    { 0x2A82,   "Anaerobic Heart Rate Upper Limit" },
    { 0x2A83,   "Anaerobic Threshold" },
    { 0x2A84,   "Aerobic Heart Rate Upper Limit" },
    { 0x2A85,   "Date of Birth" },
    { 0x2A86,   "Date of Threshold Assessment" },
    { 0x2A87,   "Email Address" },
    { 0x2A88,   "Fat Burn Heart Rate Lower Limit" },
    { 0x2A89,   "Fat Burn Heart Rate Upper Limit" },
    { 0x2A8A,   "First Name" },
    { 0x2A8B,   "Five Zone Heart Rate Limits" },
    { 0x2A8C,   "Gender" },
    { 0x2A8D,   "Heart Rate Max" },
    { 0x2A8E,   "Height" },
    { 0x2A8F,   "Hip Circumference" },
    { 0x2A90,   "Last Name" },
    { 0x2A91,   "Maximum Recommended Heart Rate" },
    { 0x2A92,   "Resting Heart Rate" },
    { 0x2A93,   "Sport Type for Aerobic and Anaerobic Thresholds" },
    { 0x2A94,   "Three Zone Heart Rate Limits" },
    { 0x2A95,   "Two Zone Heart Rate Limit" },
    { 0x2A96,   "VO2 Max" },
    { 0x2A97,   "Waist Circumference" },
    { 0x2A98,   "Weight" },
    { 0x2A99,   "Database Change Increment" },
    { 0x2A9A,   "User Index" },
    { 0x2A9B,   "Body Composition Feature" },
    { 0x2A9C,   "Body Composition Measurement" },
    { 0x2A9D,   "Weight Measurement" },
    { 0x2A9E,   "Weight Scale Feature" },
    { 0x2A9F,   "User Control Point" },
    { 0x2AA0,   "Magnetic Flux Density - 2D" },
    { 0x2AA1,   "Magnetic Flux Density - 3D" },
    { 0x2AA2,   "Language" },
    { 0x2AA3,   "Barometric Pressure Trend" },
    { 0x2AA4,   "Bond Management Control Point" },
    { 0x2AA5,   "Bond Management Feature" },
    { 0x2AA6,   "Central Address Resolution" },
    { 0x2AA7,   "CGM Measurement" },
    { 0x2AA8,   "CGM Feature" },
    { 0x2AA9,   "CGM Status" },
    { 0x2AAA,   "CGM Session Start Time" },
    { 0x2AAB,   "CGM Session Run Time" },
    { 0x2AAC,   "CGM Specific Ops Control Point" },
    { 0x2AAD,   "Indoor Positioning Configuration" },
    { 0x2AAE,   "Latitude" },
    { 0x2AAF,   "Longitude" },
    { 0x2AB0,   "Local North Coordinate" },
    { 0x2AB1,   "Local East Coordinate" },
    { 0x2AB2,   "Floor Number" },
    { 0x2AB3,   "Altitude" },
    { 0x2AB4,   "Uncertainty" },
    { 0x2AB5,   "Location Name" },
    { 0x2AB6,   "URI" },
    { 0x2AB7,   "HTTP Headers" },
    { 0x2AB8,   "HTTP Status Code" },
    { 0x2AB9,   "HTTP Entity Body" },
    { 0x2ABA,   "HTTP Control Point" },
    { 0x2ABB,   "HTTPS Security" },
    { 0x2ABC,   "TDS Control Point" },
    { 0x2ABD,   "OTS Feature" },
    { 0x2ABE,   "Object Name" },
    { 0x2ABF,   "Object Type" },
    { 0x2AC0,   "Object Size" },
    { 0x2AC1,   "Object First-Created" },
    { 0x2AC2,   "Object Last-Modified" },
    { 0x2AC3,   "Object ID" },
    { 0x2AC4,   "Object Properties" },
    { 0x2AC5,   "Object Action Control Point" },
    { 0x2AC6,   "Object List Control Point" },
    { 0x2AC7,   "Object List Filter" },
    { 0x2AC8,   "Object Changed" },
    { 0x2AC9,   "Resolvable Private Address Only" },
    { 0x2ACC,   "Fitness Machine Feature" },
    { 0x2ACD,   "Treadmill Data" },
    { 0x2ACE,   "Cross Trainer Data" },
    { 0x2ACF,   "Step Climber Data" },
    { 0x2AD0,   "Stair Climber Data" },
    { 0x2AD1,   "Rower Data" },
    { 0x2AD2,   "Indoor Bike Data" },
    { 0x2AD3,   "Training Status" },
    { 0x2AD4,   "Supported Speed Range" },
    { 0x2AD5,   "Supported Inclination Range" },
    { 0x2AD6,   "Supported Resistance Level Range" },
    { 0x2AD7,   "Supported Heart Rate Range" },
    { 0x2AD8,   "Supported Power Range" },
    { 0x2AD9,   "Fitness Machine Control Point" },
    { 0x2ADA,   "Fitness Machine Status" },
    /* (break) Characteristics, will be continuated below Mesh */
    /* Mesh Characteristics - https://www.bluetooth.com/specifications/mesh-specifications/mesh-characteristics */
    { 0x2ADB,   "Mesh Provisioning Data In" },
    { 0x2ADC,   "Mesh Provisioning Data Out" },
    { 0x2ADD,   "Mesh Proxy Data In" },
    { 0x2ADE,   "Mesh Proxy Data Out" },
    { 0x2AE0,   "Average Current" },
    { 0x2AE1,   "Average Voltage" },
    { 0x2AE2,   "Boolean" },
    { 0x2AE3,   "Chromatic Distance From Planckian" },
    { 0x2AE4,   "Chromaticity Coordinates" },
    { 0x2AE5,   "Chromaticity In CCT And Duv Values" },
    { 0x2AE6,   "Chromaticity Tolerance" },
    { 0x2AE7,   "CIE 13.3-1995 Color Rendering Index" },
    { 0x2AE8,   "Coefficient" },
    { 0x2AE9,   "Correlated Color Temperature" },
    { 0x2AEA,   "Count 16" },
    { 0x2AEB,   "Count 24" },
    { 0x2AEC,   "Country Code" },
    { 0x2AED,   "Date UTC" },
    { 0x2AEE,   "Electric Current" },
    { 0x2AEF,   "Electric Current Range" },
    { 0x2AF0,   "Electric Current Specification" },
    { 0x2AF1,   "Electric Current Statistics" },
    { 0x2AF2,   "Energy" },
    { 0x2AF3,   "Energy In A Period Of Day" },
    { 0x2AF4,   "Event Statistics" },
    { 0x2AF5,   "Fixed String 16" },
    { 0x2AF6,   "Fixed String 24" },
    { 0x2AF7,   "Fixed String 36" },
    { 0x2AF8,   "Fixed String 8" },
    { 0x2AF9,   "Generic Level" },
    { 0x2AFA,   "Global Trade Item Number" },
    { 0x2AFB,   "Illuminance" },
    { 0x2AFC,   "Luminous Efficacy" },
    { 0x2AFD,   "Luminous Energy" },
    { 0x2AFE,   "Luminous Exposure" },
    { 0x2AFF,   "Luminous Flux" },
    { 0x2B00,   "Luminous Flux Range" },
    { 0x2B01,   "Luminous Intensity" },
    { 0x2B02,   "Mass Flow" },
    { 0x2B03,   "Perceived Lightness" },
    { 0x2B04,   "Percentage 8" },
    { 0x2B05,   "Power" },
    { 0x2B06,   "Power Specification" },
    { 0x2B07,   "Relative Runtime In A Current Range" },
    { 0x2B08,   "Relative Runtime In A Generic Level Range" },
    { 0x2B09,   "Relative Value In A Voltage Range" },
    { 0x2B0A,   "Relative Value In An Illuminance Range" },
    { 0x2B0B,   "Relative Value In A Period of Day" },
    { 0x2B0C,   "Relative Value In A Temperature Range" },
    { 0x2B0D,   "Temperature 8" },
    { 0x2B0E,   "Temperature 8 In A Period Of Day" },
    { 0x2B0F,   "Temperature 8 Statistics" },
    { 0x2B10,   "Temperature Range" },
    { 0x2B11,   "Temperature Statistics" },
    { 0x2B12,   "Time Decihour 8" },
    { 0x2B13,   "Time Exponential 8" },
    { 0x2B14,   "Time Hour 24" },
    { 0x2B15,   "Time Millisecond 24" },
    { 0x2B16,   "Time Second 16" },
    { 0x2B17,   "Time Second 8" },
    { 0x2B18,   "Voltage" },
    { 0x2B19,   "Voltage Specification" },
    { 0x2B1A,   "Voltage Statistics" },
    { 0x2B1B,   "Volume Flow" },
    { 0x2B1C,   "Chromaticity Coordinate" },
    /* (continuation) Characteristics - https://www.bluetooth.com/specifications/gatt/characteristics */
    { 0x2B1D,   "Reconnection Configuration Feature" },
    { 0x2B1E,   "Reconnection Configuration Settings" },
    { 0x2B1F,   "Reconnection Configuration Control Point" },
    { 0x2B20,   "IDD Status Changed" },
    { 0x2B21,   "IDD Status" },
    { 0x2B22,   "IDD Annunciation Status" },
    { 0x2B23,   "IDD Features" },
    { 0x2B24,   "IDD Status Reader Control Point" },
    { 0x2B25,   "IDD Command Control Point" },
    { 0x2B26,   "IDD Command Data" },
    { 0x2B27,   "IDD Record Access Control Point" },
    { 0x2B28,   "IDD History Data" },
    { 0x2B29,   "Client Supported Features" },
    { 0x2B2A,   "Database Hash" },
    { 0x2B2B,   "BSS Control Point" },
    { 0x2B2C,   "BSS Response" },
    { 0x2B2D,   "Emergency ID" },
    { 0x2B2E,   "Emergency Text" },
    { 0x2B37,   "Registered User Characteristic" },
    { 0x2B3A,   "Server Supported Features" },
    { 0x2B3B,   "Physical Activity Monitor Features" },
    { 0x2B3C,   "General Activity Instantaneous Data" },
    { 0x2B3D,   "General Activity Summary Data" },
    { 0x2B3E,   "CardioRespiratory Activity Instantaneous Data" },
    { 0x2B3F,   "CardioRespiratory Activity Summary Data" },
    { 0x2B40,   "Step Counter Activity Summary Data " },
    { 0x2B41,   "Sleep Activity Instantaneous Data" },
    { 0x2B42,   "Sleep Activity Summary Data" },
    { 0x2B43,   "Physical Activity Monitor Control Point" },
    { 0x2B44,   "Current Session" },
    { 0x2B45,   "Session" },
    { 0x2B46,   "Preferred Units" },
    { 0x2B47,   "High Resolution Height" },
    { 0x2B48,   "Middle Name" },
    { 0x2B49,   "Stride Length" },
    { 0x2B4A,   "Handedness" },
    { 0x2B4B,   "Device Wearing Position" },
    { 0x2B4C,   "Four Zone Heart Rate Limits" },
    { 0x2B4D,   "High Intensity Exercise Threshold" },
    { 0x2B4E,   "Activity Goal" },
    { 0x2B4F,   "Sedentary Interval Notification" },
    { 0x2B50,   "Caloric Intake" },
    { 0x2B77,   "Audio Input State" },
    { 0x2B78,   "Gain Settings Attribute" },
    { 0x2B79,   "Audio Input Type" },
    { 0x2B7A,   "Audio Input Status" },
    { 0x2B7B,   "Audio Input Control Point" },
    { 0x2B7C,   "Audio Input Description" },
    { 0x2B7D,   "Volume State" },
    { 0x2B7E,   "Volume Control Point" },
    { 0x2B7F,   "Volume Flags" },
    { 0x2B80,   "Offset State" },
    { 0x2B81,   "Audio Location" },
    { 0x2B82,   "Volume Offset Control Point" },
    { 0x2B83,   "Audio Output Description" },
    { 0x2B84,   "Set Identity Resolving Key Characteristic" },
    { 0x2B85,   "Size Characteristic" },
    { 0x2B86,   "Lock Characteristic" },
    { 0x2B87,   "Rank Characteristic" },
    { 0x2B8E,   "Device Time Feature" },
    { 0x2B8F,   "Device Time Parameters" },
    { 0x2B90,   "Device Time" },
    { 0x2B91,   "Device Time Control Point" },
    { 0x2B92,   "Time Change Log Data" },
    { 0x2B93,   "Media Player Name" },
    { 0x2B94,   "Media Player Icon Object ID" },
    { 0x2B95,   "Media Player Icon URL" },
    { 0x2B96,   "Track Changed" },
    { 0x2B97,   "Track Title" },
    { 0x2B98,   "Track Duration" },
    { 0x2B99,   "Track Position" },
    { 0x2B9A,   "Playback Speed" },
    { 0x2B9B,   "Seeking Speed" },
    { 0x2B9C,   "Current Track Segments Object ID" },
    { 0x2B9D,   "Current Track Object ID " },
    { 0x2B9E,   "Next Track Object ID" },
    { 0x2B9F,   "Parent Group Object ID" },
    { 0x2BA0,   "Current Group Object ID" },
    { 0x2BA1,   "Playing Order" },
    { 0x2BA2,   "Playing Orders Supported" },
    { 0x2BA3,   "Media State" },
    { 0x2BA4,   "Media Control Point" },
    { 0x2BA5,   "Media Control Point Opcodes Supported" },
    { 0x2BA6,   "Search Results Object ID" },
    { 0x2BA7,   "Search Control Point" },
    { 0x2BA9,   "Media Player Icon Object Type" },
    { 0x2BAA,   "Track Segments Object Type" },
    { 0x2BAB,   "Track Object Type" },
    { 0x2BAC,   "Group Object Type" },
    { 0x2BAD,   "Constant Tone Extension Enable" },
    { 0x2BAE,   "Advertising Constant Tone Extension Minimum Length" },
    { 0x2BAF,   "Advertising Constant Tone Extension Minimum Transmit Count" },
    { 0x2BB0,   "Advertising Constant Tone Extension Transmit Duration" },
    { 0x2BB1,   "Advertising Constant Tone Extension Interval" },
    { 0x2BB2,   "Advertising Constant Tone Extension PHY" },
    { 0x2BB3,   "Bearer Provider Name" },
    { 0x2BB4,   "Bearer UCI" },
    { 0x2BB5,   "Bearer Technology" },
    { 0x2BB6,   "Bearer URI Schemes Supported List" },
    { 0x2BB7,   "Bearer Signal Strength" },
    { 0x2BB8,   "Bearer Signal Strength Reporting Interval" },
    { 0x2BB9,   "Bearer List Current Calls" },
    { 0x2BBA,   "Content Control ID" },
    { 0x2BBB,   "Status Flags" },
    { 0x2BBC,   "Incoming Call Target Bearer URI" },
    { 0x2BBD,   "Call State" },
    { 0x2BBE,   "Call Control Point" },
    { 0x2BBF,   "Call Control Point Optional Opcodes" },
    { 0x2BC0,   "Termination Reason" },
    { 0x2BC1,   "Incoming Call" },
    { 0x2BC2,   "Call Friendly Name" },
    { 0x2BC3,   "Mute" },
    { 0x2BC4,   "Sink ASE" },
    { 0x2BC5,   "Source ASE" },
    { 0x2BC6,   "ASE Control Point" },
    { 0x2BC7,   "Broadcast Audio Scan Control Point" },
    { 0x2BC8,   "Broadcast Receive State" },
    { 0x2BC9,   "Sink PAC" },
    { 0x2BCA,   "Sink Audio Locations" },
    { 0x2BCB,   "Source PAC" },
    { 0x2BCC,   "Source Audio Locations" },
    { 0x2BCD,   "Available Audio Contexts" },
    { 0x2BCE,   "Supported Audio Contexts" },
    { 0x2BCF,   "Ammonia Concentration" },
    { 0x2BD0,   "Carbon Monoxide Concentration" },
    { 0x2BD1,   "Methane Concentration" },
    { 0x2BD2,   "Nitrogen Dioxide Concentration" },
    { 0x2BD3,   "Non-Methane Volatile Organic Compounds Concentration" },
    { 0x2BD4,   "Ozone Concentration" },
    { 0x2BD5,   "Particulate Matter - PM1 Concentration" },
    { 0x2BD6,   "Particulate Matter - PM2.5 Concentration" },
    { 0x2BD7,   "Particulate Matter - PM10 Concentration" },
    { 0x2BD8,   "Sulfur Dioxide Concentration" },
    { 0x2BD9,   "Sulfur Hexafluoride Concentration" },
    /*  16-bit UUID for Members - https://www.bluetooth.com/specifications/assigned-numbers/16-bit-uuids-for-members */
    { 0xFD6F,   "Google/Apple Exposure Notification Service" },
    { 0xFD71,   "GN Hearing A/S" },
    { 0xFD72,   "Logitech International SA" },
    { 0xFD73,   "BRControls Products BV" },
    { 0xFD74,   "BRControls Products BV" },
    { 0xFD75,   "Insulet Corporation" },
    { 0xFD76,   "Insulet Corporation" },
    { 0xFD77,   "Withings" },
    { 0xFD78,   "Withings" },
    { 0xFD79,   "Withings" },
    { 0xFD7A,   "Withings" },
    { 0xFD7B,   "WYZE LABS, INC." },
    { 0xFD7C,   "Toshiba Information Systems(Japan) Corporation" },
    { 0xFD7D,   "Center for Advanced Research Wernher Von Braun" },
    { 0xFD7E,   "Samsung Electronics Co., Ltd." },
    { 0xFD7F,   "Husqvarna AB" },
    { 0xFD80,   "Phindex Technologies, Inc" },
    { 0xFD81,   "CANDY HOUSE, Inc." },
    { 0xFD82,   "Sony Corporation" },
    { 0xFD83,   "iNFORM Technology GmbH" },
    { 0xFD84,   "Tile, Inc." },
    { 0xFD85,   "Husqvarna AB" },
    { 0xFD86,   "Abbott" },
    { 0xFD87,   "Google LLC" },
    { 0xFD88,   "Urbanminded LTD" },
    { 0xFD89,   "Urbanminded LTD" },
    { 0xFD8A,   "Signify Netherlands B.V." },
    { 0xFD8B,   "Jigowatts Inc." },
    { 0xFD8C,   "Google LLC" },
    { 0xFD8D,   "quip NYC Inc." },
    { 0xFD8E,   "Motorola Solutions" },
    { 0xFD8F,   "Matrix ComSec Pvt. Ltd." },
    { 0xFD90,   "Guangzhou SuperSound Information Technology Co.,Ltd" },
    { 0xFD91,   "Groove X, Inc." },
    { 0xFD92,   "Qualcomm Technologies International, Ltd. (QTIL)" },
    { 0xFD93,   "Bayerische Motoren Werke AG" },
    { 0xFD94,   "Hewlett Packard Enterprise" },
    { 0xFD95,   "Rigado" },
    { 0xFD96,   "Google LLC" },
    { 0xFD97,   "June Life, Inc." },
    { 0xFD98,   "Disney Worldwide Services, Inc." },
    { 0xFD99,   "ABB Oy" },
    { 0xFD9A,   "Huawei Technologies Co., Ltd." },
    { 0xFD9B,   "Huawei Technologies Co., Ltd." },
    { 0xFD9C,   "Huawei Technologies Co., Ltd." },
    { 0xFD9D,   "Gastec Corporation" },
    { 0xFD9E,   "The Coca-Cola Company" },
    { 0xFD9F,   "VitalTech Affiliates LLC" },
    { 0xFDA0,   "Secugen Corporation" },
    { 0xFDA1,   "Groove X, Inc" },
    { 0xFDA2,   "Groove X, Inc" },
    { 0xFDA3,   "Inseego Corp." },
    { 0xFDA4,   "Inseego Corp." },
    { 0xFDA5,   "Neurostim OAB, Inc." },
    { 0xFDA6,   "WWZN Information Technology Company Limited" },
    { 0xFDA7,   "WWZN Information Technology Company Limited" },
    { 0xFDA8,   "PSA Peugeot Citroen" },
    { 0xFDA9,   "Rhombus Systems, Inc." },
    { 0xFDAA,   "Xiaomi Inc." },
    { 0xFDAB,   "Xiaomi Inc." },
    { 0xFDAC,   "Tentacle Sync GmbH" },
    { 0xFDAD,   "Houwa System Design, k.k." },
    { 0xFDAE,   "Houwa System Design, k.k." },
    { 0xFDAF,   "Wiliot LTD" },
    { 0xFDB0,   "Proxy Technologies, Inc." },
    { 0xFDB1,   "Proxy Technologies, Inc." },
    { 0xFDB2,   "Portable Multimedia Ltd" },
    { 0xFDB3,   "Audiodo AB" },
    { 0xFDB4,   "HP Inc" },
    { 0xFDB5,   "ECSG" },
    { 0xFDB6,   "GWA Hygiene GmbH" },
    { 0xFDB7,   "LivaNova USA Inc." },
    { 0xFDB8,   "LivaNova USA Inc." },
    { 0xFDB9,   "Comcast Cable Corporation" },
    { 0xFDBA,   "Comcast Cable Corporation" },
    { 0xFDBB,   "Profoto" },
    { 0xFDBC,   "Emerson" },
    { 0xFDBD,   "Clover Network, Inc." },
    { 0xFDBE,   "California Things Inc." },
    { 0xFDBF,   "California Things Inc." },
    { 0xFDC0,   "Hunter Douglas" },
    { 0xFDC1,   "Hunter Douglas" },
    { 0xFDC2,   "Baidu Online Network Technology (Beijing) Co., Ltd" },
    { 0xFDC3,   "Baidu Online Network Technology (Beijing) Co., Ltd" },
    { 0xFDC4,   "Simavita (Aust) Pty Ltd" },
    { 0xFDC5,   "Automatic Labs" },
    { 0xFDC6,   "Eli Lilly and Company" },
    { 0xFDC7,   "Eli Lilly and Company" },
    { 0xFDC8,   "Hach Danaher" },
    { 0xFDC9,   "Busch-Jaeger Elektro GmbH" },
    { 0xFDCA,   "Fortin Electronic Systems" },
    { 0xFDCB,   "Meggitt SA" },
    { 0xFDCC,   "Shoof Technologies" },
    { 0xFDCD,   "Qingping Technology (Beijing) Co., Ltd." },
    { 0xFDCE,   "SENNHEISER electronic GmbH & Co. KG" },
    { 0xFDCF,   "Nalu Medical, Inc" },
    { 0xFDD0,   "Huawei Technologies Co., Ltd" },
    { 0xFDD1,   "Huawei Technologies Co., Ltd" },
    { 0xFDD2,   "Bose Corporation" },
    { 0xFDD3,   "FUBA Automotive Electronics GmbH" },
    { 0xFDD4,   "LX Solutions Pty Limited" },
    { 0xFDD5,   "Brompton Bicycle Ltd" },
    { 0xFDD6,   "Ministry of Supply" },
    { 0xFDD7,   "Emerson" },
    { 0xFDD8,   "Jiangsu Teranovo Tech Co., Ltd." },
    { 0xFDD9,   "Jiangsu Teranovo Tech Co., Ltd." },
    { 0xFDDA,   "MHCS" },
    { 0xFDDB,   "Samsung Electronics Co., Ltd." },
    { 0xFDDC,   "4iiii Innovations Inc." },
    { 0xFDDD,   "Arch Systems Inc" },
    { 0xFDDE,   "Noodle Technology Inc." },
    { 0xFDDF,   "Harman International" },
    { 0xFDE0,   "John Deere" },
    { 0xFDE1,   "Fortin Electronic Systems" },
    { 0xFDE2,   "Google Inc." },
    { 0xFDE3,   "Abbott Diabetes Care" },
    { 0xFDE4,   "JUUL Labs, Inc." },
    { 0xFDE5,   "SMK Corporation" },
    { 0xFDE6,   "Intelletto Technologies Inc" },
    { 0xFDE7,   "SECOM Co., LTD" },
    { 0xFDE8,   "Robert Bosch GmbH" },
    { 0xFDE9,   "Spacesaver Corporation" },
    { 0xFDEA,   "SeeScan, Inc" },
    { 0xFDEB,   "Syntronix Corporation" },
    { 0xFDEC,   "Mannkind Corporation" },
    { 0xFDED,   "Pole Star" },
    { 0xFDEE,   "Huawei Technologies Co., Ltd." },
    { 0xFDEF,   "ART AND PROGRAM, INC." },
    { 0xFDF0,   "Google Inc." },
    { 0xFDF1,   "LAMPLIGHT Co.,Ltd" },
    { 0xFDF2,   "AMICCOM Electronics Corporation" },
    { 0xFDF3,   "Amersports" },
    { 0xFDF4,   "O. E. M. Controls, Inc." },
    { 0xFDF5,   "Milwaukee Electric Tools" },
    { 0xFDF6,   "AIAIAI ApS" },
    { 0xFDF7,   "HP Inc." },
    { 0xFDF8,   "Onvocal" },
    { 0xFDF9,   "INIA" },
    { 0xFDFA,   "Tandem Diabetes Care" },
    { 0xFDFB,   "Tandem Diabetes Care" },
    { 0xFDFC,   "Optrel AG" },
    { 0xFDFD,   "RecursiveSoft Inc." },
    { 0xFDFE,   "ADHERIUM(NZ) LIMITED" },
    { 0xFDFF,   "OSRAM GmbH" },
    { 0xFE00,   "Amazon.com Services, Inc." },
    { 0xFE01,   "Duracell U.S. Operations Inc." },
    { 0xFE02,   "Robert Bosch GmbH" },
    { 0xFE03,   "Amazon.com Services, Inc." },
    { 0xFE04,   "OpenPath Security Inc" },
    { 0xFE05,   "CORE Transport Technologies NZ Limited" },
    { 0xFE06,   "Qualcomm Technologies, Inc." },
    { 0xFE07,   "Sonos, Inc." },
    { 0xFE08,   "Microsoft" },
    { 0xFE09,   "Pillsy, Inc." },
    { 0xFE0A,   "ruwido austria gmbh" },
    { 0xFE0B,   "ruwido austria gmbh" },
    { 0xFE0C,   "Procter & Gamble" },
    { 0xFE0D,   "Procter & Gamble" },
    { 0xFE0E,   "Setec Pty Ltd" },
    { 0xFE0F,   "Philips Lighting B.V." },
    { 0xFE10,   "Lapis Semiconductor Co., Ltd." },
    { 0xFE11,   "GMC-I Messtechnik GmbH" },
    { 0xFE12,   "M-Way Solutions GmbH" },
    { 0xFE13,   "Apple Inc." },
    { 0xFE14,   "Flextronics International USA Inc." },
    { 0xFE15,   "Amazon.com Services, Inc.." },
    { 0xFE16,   "Footmarks, Inc." },
    { 0xFE17,   "Telit Wireless Solutions GmbH" },
    { 0xFE18,   "Runtime, Inc." },
    { 0xFE19,   "Google, Inc" },
    { 0xFE1A,   "Tyto Life LLC" },
    { 0xFE1B,   "Tyto Life LLC" },
    { 0xFE1C,   "NetMedia, Inc." },
    { 0xFE1D,   "Illuminati Instrument Corporation" },
    { 0xFE1E,   "Smart Innovations Co., Ltd" },
    { 0xFE1F,   "Garmin International, Inc." },
    { 0xFE20,   "Emerson" },
    { 0xFE21,   "Bose Corporation" },
    { 0xFE22,   "Zoll Medical Corporation" },
    { 0xFE23,   "Zoll Medical Corporation" },
    { 0xFE24,   "August Home Inc" },
    { 0xFE25,   "Apple, Inc." },
    { 0xFE26,   "Google" },
    { 0xFE27,   "Google" },
    { 0xFE28,   "Ayla Networks" },
    { 0xFE29,   "Gibson Innovations" },
    { 0xFE2A,   "DaisyWorks, Inc." },
    { 0xFE2B,   "ITT Industries" },
    { 0xFE2C,   "Google" },
    { 0xFE2D,   "SMART INNOVATION Co.,Ltd" },
    { 0xFE2E,   "ERi,Inc." },
    { 0xFE2F,   "CRESCO Wireless, Inc" },
    { 0xFE30,   "Volkswagen AG" },
    { 0xFE31,   "Volkswagen AG" },
    { 0xFE32,   "Pro-Mark, Inc." },
    { 0xFE33,   "CHIPOLO d.o.o." },
    { 0xFE34,   "SmallLoop LLC" },
    { 0xFE35,   "HUAWEI Technologies Co., Ltd" },
    { 0xFE36,   "HUAWEI Technologies Co., Ltd" },
    { 0xFE37,   "Spaceek LTD" },
    { 0xFE38,   "Spaceek LTD" },
    { 0xFE39,   "TTS Tooltechnic Systems AG & Co. KG" },
    { 0xFE3A,   "TTS Tooltechnic Systems AG & Co. KG" },
    { 0xFE3B,   "Dobly Laboratories" },
    { 0xFE3C,   "alibaba" },
    { 0xFE3D,   "BD Medical" },
    { 0xFE3E,   "BD Medical" },
    { 0xFE3F,   "Friday Labs Limited" },
    { 0xFE40,   "Inugo Systems Limited" },
    { 0xFE41,   "Inugo Systems Limited" },
    { 0xFE42,   "Nets A/S" },
    { 0xFE43,   "Andreas Stihl AG & Co. KG" },
    { 0xFE44,   "SK Telecom" },
    { 0xFE45,   "Snapchat Inc" },
    { 0xFE46,   "B&O Play A/S" },
    { 0xFE47,   "General Motors" },
    { 0xFE48,   "General Motors" },
    { 0xFE49,   "SenionLab AB" },
    { 0xFE4A,   "OMRON HEALTHCARE Co., Ltd." },
    { 0xFE4B,   "Philips Lighting B.V." },
    { 0xFE4C,   "Volkswagen AG" },
    { 0xFE4D,   "Casambi Technologies Oy" },
    { 0xFE4E,   "NTT docomo" },
    { 0xFE4F,   "Molekule, Inc." },
    { 0xFE50,   "Google Inc." },
    { 0xFE51,   "SRAM" },
    { 0xFE52,   "SetPoint Medical" },
    { 0xFE53,   "3M" },
    { 0xFE54,   "Motiv, Inc." },
    { 0xFE55,   "Google Inc." },
    { 0xFE56,   "Google Inc." },
    { 0xFE57,   "Dotted Labs" },
    { 0xFE58,   "Nordic Semiconductor ASA" },
    { 0xFE59,   "Nordic Semiconductor ASA" },
    { 0xFE5A,   "Cronologics Corporation" },
    { 0xFE5B,   "GT-tronics HK Ltd" },
    { 0xFE5C,   "million hunters GmbH" },
    { 0xFE5D,   "Grundfos A/S" },
    { 0xFE5E,   "Plastc Corporation" },
    { 0xFE5F,   "Eyefi, Inc." },
    { 0xFE60,   "Lierda Science & Technology Group Co., Ltd." },
    { 0xFE61,   "Logitech International SA" },
    { 0xFE62,   "Indagem Tech LLC" },
    { 0xFE63,   "Connected Yard, Inc." },
    { 0xFE64,   "Siemens AG" },
    { 0xFE65,   "CHIPOLO d.o.o." },
    { 0xFE66,   "Intel Corporation" },
    { 0xFE67,   "Lab Sensor Solutions" },
    { 0xFE68,   "Qualcomm Life Inc" },
    { 0xFE69,   "Qualcomm Life Inc" },
    { 0xFE6A,   "Kontakt Micro-Location Sp. z o.o." },
    { 0xFE6B,   "TASER International, Inc." },
    { 0xFE6C,   "TASER International, Inc." },
    { 0xFE6D,   "The University of Tokyo" },
    { 0xFE6E,   "The University of Tokyo" },
    { 0xFE6F,   "LINE Corporation" },
    { 0xFE70,   "Beijing Jingdong Century Trading Co., Ltd." },
    { 0xFE71,   "Plume Design Inc" },
    { 0xFE72,   "St. Jude Medical, Inc." },
    { 0xFE73,   "St. Jude Medical, Inc." },
    { 0xFE74,   "unwire" },
    { 0xFE75,   "TangoMe" },
    { 0xFE76,   "TangoMe" },
    { 0xFE77,   "Hewlett-Packard Company" },
    { 0xFE78,   "Hewlett-Packard Company" },
    { 0xFE79,   "Zebra Technologies" },
    { 0xFE7A,   "Bragi GmbH" },
    { 0xFE7B,   "Orion Labs, Inc." },
    { 0xFE7C,   "Telit Wireless Solutions (Formerly Stollmann E+V GmbH)" },
    { 0xFE7D,   "Aterica Health Inc." },
    { 0xFE7E,   "Awear Solutions Ltd" },
    { 0xFE7F,   "Doppler Lab" },
    { 0xFE80,   "Doppler Lab" },
    { 0xFE81,   "Medtronic Inc." },
    { 0xFE82,   "Medtronic Inc." },
    { 0xFE83,   "Blue Bite" },
    { 0xFE84,   "RF Digital Corp" },
    { 0xFE85,   "RF Digital Corp" },
    { 0xFE86,   "HUAWEI Technologies Co., Ltd. ( )" },
    { 0xFE87,   "Qingdao Yeelink Information Technology Co., Ltd. ( )" },
    { 0xFE88,   "SALTO SYSTEMS S.L." },
    { 0xFE89,   "B&O Play A/S" },
    { 0xFE8A,   "Apple, Inc." },
    { 0xFE8B,   "Apple, Inc." },
    { 0xFE8C,   "TRON Forum" },
    { 0xFE8D,   "Interaxon Inc." },
    { 0xFE8E,   "ARM Ltd" },
    { 0xFE8F,   "CSR" },
    { 0xFE90,   "JUMA" },
    { 0xFE91,   "Shanghai Imilab Technology Co.,Ltd" },
    { 0xFE92,   "Jarden Safety & Security" },
    { 0xFE93,   "OttoQ In" },
    { 0xFE94,   "OttoQ In" },
    { 0xFE95,   "Xiaomi Inc." },
    { 0xFE96,   "Tesla Motors Inc." },
    { 0xFE97,   "Tesla Motors Inc." },
    { 0xFE98,   "Currant Inc" },
    { 0xFE99,   "Currant Inc" },
    { 0xFE9A,   "Estimote" },
    { 0xFE9B,   "Samsara Networks, Inc" },
    { 0xFE9C,   "GSI Laboratories, Inc." },
    { 0xFE9D,   "Mobiquity Networks Inc" },
    { 0xFE9E,   "Dialog Semiconductor B.V." },
    { 0xFE9F,   "Google" },
    { 0xFEA0,   "Google" },
    { 0xFEA1,   "Intrepid Control Systems, Inc." },
    { 0xFEA2,   "Intrepid Control Systems, Inc." },
    { 0xFEA3,   "ITT Industries" },
    { 0xFEA4,   "Paxton Access Ltd" },
    { 0xFEA5,   "GoPro, Inc." },
    { 0xFEA6,   "GoPro, Inc." },
    { 0xFEA7,   "UTC Fire and Security" },
    { 0xFEA8,   "Savant Systems LLC" },
    { 0xFEA9,   "Savant Systems LLC" },
    { 0xFEAA,   "Google" },
    { 0xFEAB,   "Nokia" },
    { 0xFEAC,   "Nokia" },
    { 0xFEAD,   "Nokia" },
    { 0xFEAE,   "Nokia" },
    { 0xFEAF,   "Nest Labs Inc" },
    { 0xFEB0,   "Nest Labs Inc" },
    { 0xFEB1,   "Electronics Tomorrow Limited" },
    { 0xFEB2,   "Microsoft Corporation" },
    { 0xFEB3,   "Taobao" },
    { 0xFEB4,   "WiSilica Inc." },
    { 0xFEB5,   "WiSilica Inc." },
    { 0xFEB6,   "Vencer Co., Ltd" },
    { 0xFEB7,   "Facebook, Inc." },
    { 0xFEB8,   "Facebook, Inc." },
    { 0xFEB9,   "LG Electronics" },
    { 0xFEBA,   "Tencent Holdings Limited" },
    { 0xFEBB,   "adafruit industries" },
    { 0xFEBC,   "Dexcom Inc" },
    { 0xFEBD,   "Clover Network, Inc" },
    { 0xFEBE,   "Bose Corporation" },
    { 0xFEBF,   "Nod, Inc." },
    { 0xFEC0,   "KDDI Corporation" },
    { 0xFEC1,   "KDDI Corporation" },
    { 0xFEC2,   "Blue Spark Technologies, Inc." },
    { 0xFEC3,   "360fly, Inc." },
    { 0xFEC4,   "PLUS Location Systems" },
    { 0xFEC5,   "Realtek Semiconductor Corp." },
    { 0xFEC6,   "Kocomojo, LLC" },
    { 0xFEC7,   "Apple, Inc." },
    { 0xFEC8,   "Apple, Inc." },
    { 0xFEC9,   "Apple, Inc." },
    { 0xFECA,   "Apple, Inc." },
    { 0xFECB,   "Apple, Inc." },
    { 0xFECC,   "Apple, Inc." },
    { 0xFECD,   "Apple, Inc." },
    { 0xFECE,   "Apple, Inc." },
    { 0xFECF,   "Apple, Inc." },
    { 0xFED0,   "Apple, Inc." },
    { 0xFED1,   "Apple, Inc." },
    { 0xFED2,   "Apple, Inc." },
    { 0xFED3,   "Apple, Inc." },
    { 0xFED4,   "Apple, Inc." },
    { 0xFED5,   "Plantronics Inc." },
    { 0xFED6,   "Broadcom" },
    { 0xFED7,   "Broadcom" },
    { 0xFED8,   "Google" },
    { 0xFED9,   "Pebble Technology Corporation" },
    { 0xFEDA,   "ISSC Technologies Corp." },
    { 0xFEDB,   "Perka, Inc." },
    { 0xFEDC,   "Jawbone" },
    { 0xFEDD,   "Jawbone" },
    { 0xFEDE,   "Coin, Inc." },
    { 0xFEDF,   "Design SHIFT" },
    { 0xFEE0,   "Anhui Huami Information Technology Co., Ltd." },
    { 0xFEE1,   "Anhui Huami Information Technology Co., Ltd." },
    { 0xFEE2,   "Anki, Inc." },
    { 0xFEE3,   "Anki, Inc." },
    { 0xFEE4,   "Nordic Semiconductor ASA" },
    { 0xFEE5,   "Nordic Semiconductor ASA" },
    { 0xFEE6,   "Silvair, Inc." },
    { 0xFEE7,   "Tencent Holdings Limited." },
    { 0xFEE8,   "Quintic Corp." },
    { 0xFEE9,   "Quintic Corp." },
    { 0xFEEA,   "Swirl Networks, Inc." },
    { 0xFEEB,   "Swirl Networks, Inc." },
    { 0xFEEC,   "Tile, Inc." },
    { 0xFEED,   "Tile, Inc." },
    { 0xFEEE,   "Polar Electro Oy" },
    { 0xFEEF,   "Polar Electro Oy" },
    { 0xFEF0,   "Intel" },
    { 0xFEF1,   "CSR" },
    { 0xFEF2,   "CSR" },
    { 0xFEF3,   "Google" },
    { 0xFEF4,   "Google" },
    { 0xFEF5,   "Dialog Semiconductor GmbH" },
    { 0xFEF6,   "Wicentric, Inc." },
    { 0xFEF7,   "Aplix Corporation" },
    { 0xFEF8,   "Aplix Corporation" },
    { 0xFEF9,   "PayPal, Inc." },
    { 0xFEFA,   "PayPal, Inc." },
    { 0xFEFB,   "Telit Wireless Solutions (Formerly Stollmann E+V GmbH)" },
    { 0xFEFC,   "Gimbal, Inc." },
    { 0xFEFD,   "Gimbal, Inc." },
    { 0xFEFE,   "GN ReSound A/S" },
    { 0xFEFF,   "GN Netcom" },
    /* SDO Uuids - https://www.bluetooth.com/specifications/assigned-numbers/16-bit-uuids-for-sdos */
    { 0xFFF8,   "Mopria Alliance - Mopria Alliance BLE Service" },
    { 0xFFF9,   "Fast IDentity Online Alliance (FIDO) - FIDO2 secure client-to-authenticator transport" },
    { 0xFFFA,   "ASTM International - ASTM Remote ID" },
    { 0xFFFB,   "Thread Group, Inc. - Direct Thread Commissioning" },
    { 0xFFFC,   "AirFuel Alliance - Wireless Power Transfer (WPT) Service" },
    { 0xFFFD,   "Fast IDentity Online Alliance - Universal Second Factor Authenticator Service" },
    { 0xFFFE,   "Alliance for Wireless Power - Wireless Power Transfer Service" },
    { 0, NULL }
};
value_string_ext bluetooth_uuid_vals_ext = VALUE_STRING_EXT_INIT(bluetooth_uuid_vals);

/* Taken from https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers */
static const value_string bluetooth_company_id_vals[] = {
    { 0x0000,   "Ericsson Technology Licensing" },
    { 0x0001,   "Nokia Mobile Phones" },
    { 0x0002,   "Intel Corp." },
    { 0x0003,   "IBM Corp." },
    { 0x0004,   "Toshiba Corp." },
    { 0x0005,   "3Com" },
    { 0x0006,   "Microsoft" },
    { 0x0007,   "Lucent" },
    { 0x0008,   "Motorola" },
    { 0x0009,   "Infineon Technologies AG" },
    { 0x000A,   "Qualcomm Technologies International, Ltd. (QTIL)" },
    { 0x000B,   "Silicon Wave" },
    { 0x000C,   "Digianswer A/S" },
    { 0x000D,   "Texas Instruments Inc." },
    { 0x000E,   "Parthus Technologies Inc." },
    { 0x000F,   "Broadcom Corporation" },
    { 0x0010,   "Mitel Semiconductor" },
    { 0x0011,   "Widcomm, Inc." },
    { 0x0012,   "Zeevo, Inc." },
    { 0x0013,   "Atmel Corporation" },
    { 0x0014,   "Mitsubishi Electric Corporation" },
    { 0x0015,   "RTX Telecom A/S" },
    { 0x0016,   "KC Technology Inc." },
    { 0x0017,   "Newlogic" },
    { 0x0018,   "Transilica, Inc." },
    { 0x0019,   "Rohde & Schwarz GmbH & Co. KG" },
    { 0x001A,   "TTPCom Limited" },
    { 0x001B,   "Signia Technologies, Inc." },
    { 0x001C,   "Conexant Systems Inc." },
    { 0x001D,   "Qualcomm" },
    { 0x001E,   "Inventel" },
    { 0x001F,   "AVM Berlin" },
    { 0x0020,   "BandSpeed, Inc." },
    { 0x0021,   "Mansella Ltd" },
    { 0x0022,   "NEC Corporation" },
    { 0x0023,   "WavePlus Technology Co., Ltd." },
    { 0x0024,   "Alcatel" },
    { 0x0025,   "NXP Semiconductors (formerly Philips Semiconductors)" },
    { 0x0026,   "C Technologies" },
    { 0x0027,   "Open Interface" },
    { 0x0028,   "R F Micro Devices" },
    { 0x0029,   "Hitachi Ltd" },
    { 0x002A,   "Symbol Technologies, Inc." },
    { 0x002B,   "Tenovis" },
    { 0x002C,   "Macronix International Co. Ltd." },
    { 0x002D,   "GCT Semiconductor" },
    { 0x002E,   "Norwood Systems" },
    { 0x002F,   "MewTel Technology Inc." },
    { 0x0030,   "ST Microelectronics" },
    { 0x0031,   "Synopsys, Inc." },
    { 0x0032,   "Red-M (Communications) Ltd" },
    { 0x0033,   "Commil Ltd" },
    { 0x0034,   "Computer Access Technology Corporation (CATC)" },
    { 0x0035,   "Eclipse (HQ Espana) S.L." },
    { 0x0036,   "Renesas Electronics Corporation" },
    { 0x0037,   "Mobilian Corporation" },
    { 0x0038,   "Syntronix Corporation" },
    { 0x0039,   "Integrated System Solution Corp." },
    { 0x003A,   "Matsushita Electric Industrial Co., Ltd." },
    { 0x003B,   "Gennum Corporation" },
    { 0x003C,   "BlackBerry Limited (formerly Research In Motion)" },
    { 0x003D,   "IPextreme, Inc." },
    { 0x003E,   "Systems and Chips, Inc" },
    { 0x003F,   "Bluetooth SIG, Inc" },
    { 0x0040,   "Seiko Epson Corporation" },
    { 0x0041,   "Integrated Silicon Solution Taiwan, Inc." },
    { 0x0042,   "CONWISE Technology Corporation Ltd" },
    { 0x0043,   "PARROT AUTOMOTIVE SAS" },
    { 0x0044,   "Socket Mobile" },
    { 0x0045,   "Atheros Communications, Inc." },
    { 0x0046,   "MediaTek, Inc." },
    { 0x0047,   "Bluegiga" },
    { 0x0048,   "Marvell Technology Group Ltd." },
    { 0x0049,   "3DSP Corporation" },
    { 0x004A,   "Accel Semiconductor Ltd." },
    { 0x004B,   "Continental Automotive Systems" },
    { 0x004C,   "Apple, Inc." },
    { 0x004D,   "Staccato Communications, Inc." },
    { 0x004E,   "Avago Technologies" },
    { 0x004F,   "APT Ltd." },
    { 0x0050,   "SiRF Technology, Inc." },
    { 0x0051,   "Tzero Technologies, Inc." },
    { 0x0052,   "J&M Corporation" },
    { 0x0053,   "Free2move AB" },
    { 0x0054,   "3DiJoy Corporation" },
    { 0x0055,   "Plantronics, Inc." },
    { 0x0056,   "Sony Ericsson Mobile Communications" },
    { 0x0057,   "Harman International Industries, Inc." },
    { 0x0058,   "Vizio, Inc." },
    { 0x0059,   "Nordic Semiconductor ASA" },
    { 0x005A,   "EM Microelectronic-Marin SA" },
    { 0x005B,   "Ralink Technology Corporation" },
    { 0x005C,   "Belkin International, Inc." },
    { 0x005D,   "Realtek Semiconductor Corporation" },
    { 0x005E,   "Stonestreet One, LLC" },
    { 0x005F,   "Wicentric, Inc." },
    { 0x0060,   "RivieraWaves S.A.S" },
    { 0x0061,   "RDA Microelectronics" },
    { 0x0062,   "Gibson Guitars" },
    { 0x0063,   "MiCommand Inc." },
    { 0x0064,   "Band XI International, LLC" },
    { 0x0065,   "Hewlett-Packard Company" },
    { 0x0066,   "9Solutions Oy" },
    { 0x0067,   "GN Netcom A/S" },
    { 0x0068,   "General Motors" },
    { 0x0069,   "A&D Engineering, Inc." },
    { 0x006A,   "MindTree Ltd." },
    { 0x006B,   "Polar Electro OY" },
    { 0x006C,   "Beautiful Enterprise Co., Ltd." },
    { 0x006D,   "BriarTek, Inc" },
    { 0x006E,   "Summit Data Communications, Inc." },
    { 0x006F,   "Sound ID" },
    { 0x0070,   "Monster, LLC" },
    { 0x0071,   "connectBlue AB" },
    { 0x0072,   "ShangHai Super Smart Electronics Co. Ltd." },
    { 0x0073,   "Group Sense Ltd." },
    { 0x0074,   "Zomm, LLC" },
    { 0x0075,   "Samsung Electronics Co. Ltd." },
    { 0x0076,   "Creative Technology Ltd." },
    { 0x0077,   "Laird Technologies" },
    { 0x0078,   "Nike, Inc." },
    { 0x0079,   "lesswire AG" },
    { 0x007A,   "MStar Semiconductor, Inc." },
    { 0x007B,   "Hanlynn Technologies" },
    { 0x007C,   "A & R Cambridge" },
    { 0x007D,   "Seers Technology Co., Ltd." },
    { 0x007E,   "Sports Tracking Technologies Ltd." },
    { 0x007F,   "Autonet Mobile" },
    { 0x0080,   "DeLorme Publishing Company, Inc." },
    { 0x0081,   "WuXi Vimicro" },
    { 0x0082,   "Sennheiser Communications A/S" },
    { 0x0083,   "TimeKeeping Systems, Inc." },
    { 0x0084,   "Ludus Helsinki Ltd." },
    { 0x0085,   "BlueRadios, Inc." },
    { 0x0086,   "Equinux AG" },
    { 0x0087,   "Garmin International, Inc." },
    { 0x0088,   "Ecotest" },
    { 0x0089,   "GN ReSound A/S" },
    { 0x008A,   "Jawbone" },
    { 0x008B,   "Topcon Positioning Systems, LLC" },
    { 0x008C,   "Gimbal Inc. (formerly Qualcomm Labs, Inc. and Qualcomm Retail Solutions, Inc.)" },
    { 0x008D,   "Zscan Software" },
    { 0x008E,   "Quintic Corp" },
    { 0x008F,   "Telit Wireless Solutions GmbH (formerly Stollmann E+V GmbH)" },
    { 0x0090,   "Funai Electric Co., Ltd." },
    { 0x0091,   "Advanced PANMOBIL systems GmbH & Co. KG" },
    { 0x0092,   "ThinkOptics, Inc." },
    { 0x0093,   "Universal Electronics, Inc." },
    { 0x0094,   "Airoha Technology Corp." },
    { 0x0095,   "NEC Lighting, Ltd." },
    { 0x0096,   "ODM Technology, Inc." },
    { 0x0097,   "ConnecteDevice Ltd." },
    { 0x0098,   "zero1.tv GmbH" },
    { 0x0099,   "i.Tech Dynamic Global Distribution Ltd." },
    { 0x009A,   "Alpwise" },
    { 0x009B,   "Jiangsu Toppower Automotive Electronics Co., Ltd." },
    { 0x009C,   "Colorfy, Inc." },
    { 0x009D,   "Geoforce Inc." },
    { 0x009E,   "Bose Corporation" },
    { 0x009F,   "Suunto Oy" },
    { 0x00A0,   "Kensington Computer Products Group" },
    { 0x00A1,   "SR-Medizinelektronik" },
    { 0x00A2,   "Vertu Corporation Limited" },
    { 0x00A3,   "Meta Watch Ltd." },
    { 0x00A4,   "LINAK A/S" },
    { 0x00A5,   "OTL Dynamics LLC" },
    { 0x00A6,   "Panda Ocean Inc." },
    { 0x00A7,   "Visteon Corporation" },
    { 0x00A8,   "ARP Devices Limited" },
    { 0x00A9,   "Magneti Marelli S.p.A" },
    { 0x00AA,   "CAEN RFID srl" },
    { 0x00AB,   "Ingenieur-Systemgruppe Zahn GmbH" },
    { 0x00AC,   "Green Throttle Games" },
    { 0x00AD,   "Peter Systemtechnik GmbH" },
    { 0x00AE,   "Omegawave Oy" },
    { 0x00AF,   "Cinetix" },
    { 0x00B0,   "Passif Semiconductor Corp" },
    { 0x00B1,   "Saris Cycling Group, Inc" },
    { 0x00B2,   "Bekey A/S" },
    { 0x00B3,   "Clarinox Technologies Pty. Ltd." },
    { 0x00B4,   "BDE Technology Co., Ltd." },
    { 0x00B5,   "Swirl Networks" },
    { 0x00B6,   "Meso international" },
    { 0x00B7,   "TreLab Ltd" },
    { 0x00B8,   "Qualcomm Innovation Center, Inc. (QuIC)" },
    { 0x00B9,   "Johnson Controls, Inc." },
    { 0x00BA,   "Starkey Laboratories Inc." },
    { 0x00BB,   "S-Power Electronics Limited" },
    { 0x00BC,   "Ace Sensor Inc" },
    { 0x00BD,   "Aplix Corporation" },
    { 0x00BE,   "AAMP of America" },
    { 0x00BF,   "Stalmart Technology Limited" },
    { 0x00C0,   "AMICCOM Electronics Corporation" },
    { 0x00C1,   "Shenzhen Excelsecu Data Technology Co.,Ltd" },
    { 0x00C2,   "Geneq Inc." },
    { 0x00C3,   "adidas AG" },
    { 0x00C4,   "LG Electronics" },
    { 0x00C5,   "Onset Computer Corporation" },
    { 0x00C6,   "Selfly BV" },
    { 0x00C7,   "Quuppa Oy." },
    { 0x00C8,   "GeLo Inc" },
    { 0x00C9,   "Evluma" },
    { 0x00CA,   "MC10" },
    { 0x00CB,   "Binauric SE" },
    { 0x00CC,   "Beats Electronics" },
    { 0x00CD,   "Microchip Technology Inc." },
    { 0x00CE,   "Elgato Systems GmbH" },
    { 0x00CF,   "ARCHOS SA" },
    { 0x00D0,   "Dexcom, Inc." },
    { 0x00D1,   "Polar Electro Europe B.V." },
    { 0x00D2,   "Dialog Semiconductor B.V." },
    { 0x00D3,   "Taixingbang Technology (HK) Co,. LTD." },
    { 0x00D4,   "Kawantech" },
    { 0x00D5,   "Austco Communication Systems" },
    { 0x00D6,   "Timex Group USA, Inc." },
    { 0x00D7,   "Qualcomm Technologies, Inc." },
    { 0x00D8,   "Qualcomm Connected Experiences, Inc." },
    { 0x00D9,   "Voyetra Turtle Beach" },
    { 0x00DA,   "txtr GmbH" },
    { 0x00DB,   "Biosentronics" },
    { 0x00DC,   "Procter & Gamble" },
    { 0x00DD,   "Hosiden Corporation" },
    { 0x00DE,   "Muzik LLC" },
    { 0x00DF,   "Misfit Wearables Corp" },
    { 0x00E0,   "Google" },
    { 0x00E1,   "Danlers Ltd" },
    { 0x00E2,   "Semilink Inc" },
    { 0x00E3,   "inMusic Brands, Inc" },
    { 0x00E4,   "L.S. Research Inc." },
    { 0x00E5,   "Eden Software Consultants Ltd." },
    { 0x00E6,   "Freshtemp" },
    { 0x00E7,   "KS Technologies" },
    { 0x00E8,   "ACTS Technologies" },
    { 0x00E9,   "Vtrack Systems" },
    { 0x00EA,   "Nielsen-Kellerman Company" },
    { 0x00EB,   "Server Technology Inc." },
    { 0x00EC,   "BioResearch Associates" },
    { 0x00ED,   "Jolly Logic, LLC" },
    { 0x00EE,   "Above Average Outcomes, Inc." },
    { 0x00EF,   "Bitsplitters GmbH" },
    { 0x00F0,   "PayPal, Inc." },
    { 0x00F1,   "Witron Technology Limited" },
    { 0x00F2,   "Morse Project Inc." },
    { 0x00F3,   "Kent Displays Inc." },
    { 0x00F4,   "Nautilus Inc." },
    { 0x00F5,   "Smartifier Oy" },
    { 0x00F6,   "Elcometer Limited" },
    { 0x00F7,   "VSN Technologies, Inc." },
    { 0x00F8,   "AceUni Corp., Ltd." },
    { 0x00F9,   "StickNFind" },
    { 0x00FA,   "Crystal Code AB" },
    { 0x00FB,   "KOUKAAM a.s." },
    { 0x00FC,   "Delphi Corporation" },
    { 0x00FD,   "ValenceTech Limited" },
    { 0x00FE,   "Stanley Black and Decker" },
    { 0x00FF,   "Typo Products, LLC" },
    { 0x0100,   "TomTom International BV" },
    { 0x0101,   "Fugoo, Inc." },
    { 0x0102,   "Keiser Corporation" },
    { 0x0103,   "Bang & Olufsen A/S" },
    { 0x0104,   "PLUS Location Systems Pty Ltd" },
    { 0x0105,   "Ubiquitous Computing Technology Corporation" },
    { 0x0106,   "Innovative Yachtter Solutions" },
    { 0x0107,   "William Demant Holding A/S" },
    { 0x0108,   "Chicony Electronics Co., Ltd." },
    { 0x0109,   "Atus BV" },
    { 0x010A,   "Codegate Ltd" },
    { 0x010B,   "ERi, Inc" },
    { 0x010C,   "Transducers Direct, LLC" },
    { 0x010D,   "Fujitsu Ten LImited" },
    { 0x010E,   "Audi AG" },
    { 0x010F,   "HiSilicon Technologies Col, Ltd." },
    { 0x0110,   "Nippon Seiki Co., Ltd." },
    { 0x0111,   "Steelseries ApS" },
    { 0x0112,   "Visybl Inc." },
    { 0x0113,   "Openbrain Technologies, Co., Ltd." },
    { 0x0114,   "Xensr" },
    { 0x0115,   "e.solutions" },
    { 0x0116,   "10AK Technologies" },
    { 0x0117,   "Wimoto Technologies Inc" },
    { 0x0118,   "Radius Networks, Inc." },
    { 0x0119,   "Wize Technology Co., Ltd." },
    { 0x011A,   "Qualcomm Labs, Inc." },
    { 0x011B,   "Hewlett Packard Enterprise" },
    { 0x011C,   "Baidu" },
    { 0x011D,   "Arendi AG" },
    { 0x011E,   "Skoda Auto a.s." },
    { 0x011F,   "Volkswagen AG" },
    { 0x0120,   "Porsche AG" },
    { 0x0121,   "Sino Wealth Electronic Ltd." },
    { 0x0122,   "AirTurn, Inc." },
    { 0x0123,   "Kinsa, Inc" },
    { 0x0124,   "HID Global" },
    { 0x0125,   "SEAT es" },
    { 0x0126,   "Promethean Ltd." },
    { 0x0127,   "Salutica Allied Solutions" },
    { 0x0128,   "GPSI Group Pty Ltd" },
    { 0x0129,   "Nimble Devices Oy" },
    { 0x012A,   "Changzhou Yongse Infotech Co., Ltd." },
    { 0x012B,   "SportIQ" },
    { 0x012C,   "TEMEC Instruments B.V." },
    { 0x012D,   "Sony Corporation" },
    { 0x012E,   "ASSA ABLOY" },
    { 0x012F,   "Clarion Co. Inc." },
    { 0x0130,   "Warehouse Innovations" },
    { 0x0131,   "Cypress Semiconductor" },
    { 0x0132,   "MADS Inc" },
    { 0x0133,   "Blue Maestro Limited" },
    { 0x0134,   "Resolution Products, Ltd." },
    { 0x0135,   "Aireware LLC" },
    { 0x0136,   "Silvair, Inc." },
    { 0x0137,   "Prestigio Plaza Ltd." },
    { 0x0138,   "NTEO Inc." },
    { 0x0139,   "Focus Systems Corporation" },
    { 0x013A,   "Tencent Holdings Ltd." },
    { 0x013B,   "Allegion" },
    { 0x013C,   "Murata Manufacturing Co., Ltd." },
    { 0x013D,   "WirelessWERX" },
    { 0x013E,   "Nod, Inc." },
    { 0x013F,   "B&B Manufacturing Company" },
    { 0x0140,   "Alpine Electronics (China) Co., Ltd" },
    { 0x0141,   "FedEx Services" },
    { 0x0142,   "Grape Systems Inc." },
    { 0x0143,   "Bkon Connect" },
    { 0x0144,   "Lintech GmbH" },
    { 0x0145,   "Novatel Wireless" },
    { 0x0146,   "Ciright" },
    { 0x0147,   "Mighty Cast, Inc." },
    { 0x0148,   "Ambimat Electronics" },
    { 0x0149,   "Perytons Ltd." },
    { 0x014A,   "Tivoli Audio, LLC" },
    { 0x014B,   "Master Lock" },
    { 0x014C,   "Mesh-Net Ltd" },
    { 0x014D,   "HUIZHOU DESAY SV AUTOMOTIVE CO., LTD." },
    { 0x014E,   "Tangerine, Inc." },
    { 0x014F,   "B&W Group Ltd." },
    { 0x0150,   "Pioneer Corporation" },
    { 0x0151,   "OnBeep" },
    { 0x0152,   "Vernier Software & Technology" },
    { 0x0153,   "ROL Ergo" },
    { 0x0154,   "Pebble Technology" },
    { 0x0155,   "NETATMO" },
    { 0x0156,   "Accumulate AB" },
    { 0x0157,   "Anhui Huami Information Technology Co., Ltd." },
    { 0x0158,   "Inmite s.r.o." },
    { 0x0159,   "ChefSteps, Inc." },
    { 0x015A,   "micas AG" },
    { 0x015B,   "Biomedical Research Ltd." },
    { 0x015C,   "Pitius Tec S.L." },
    { 0x015D,   "Estimote, Inc." },
    { 0x015E,   "Unikey Technologies, Inc." },
    { 0x015F,   "Timer Cap Co." },
    { 0x0160,   "AwoX" },
    { 0x0161,   "yikes" },
    { 0x0162,   "MADSGlobalNZ Ltd." },
    { 0x0163,   "PCH International" },
    { 0x0164,   "Qingdao Yeelink Information Technology Co., Ltd." },
    { 0x0165,   "Milwaukee Tool (Formally Milwaukee Electric Tools)" },
    { 0x0166,   "MISHIK Pte Ltd" },
    { 0x0167,   "Ascensia Diabetes Care US Inc." },
    { 0x0168,   "Spicebox LLC" },
    { 0x0169,   "emberlight" },
    { 0x016A,   "Cooper-Atkins Corporation" },
    { 0x016B,   "Qblinks" },
    { 0x016C,   "MYSPHERA" },
    { 0x016D,   "LifeScan Inc" },
    { 0x016E,   "Volantic AB" },
    { 0x016F,   "Podo Labs, Inc" },
    { 0x0170,   "Roche Diabetes Care AG" },
    { 0x0171,   "Amazon Fulfillment Service" },
    { 0x0172,   "Connovate Technology Private Limited" },
    { 0x0173,   "Kocomojo, LLC" },
    { 0x0174,   "Everykey Inc." },
    { 0x0175,   "Dynamic Controls" },
    { 0x0176,   "SentriLock" },
    { 0x0177,   "I-SYST inc." },
    { 0x0178,   "CASIO COMPUTER CO., LTD." },
    { 0x0179,   "LAPIS Semiconductor Co., Ltd." },
    { 0x017A,   "Telemonitor, Inc." },
    { 0x017B,   "taskit GmbH" },
    { 0x017C,   "Daimler AG" },
    { 0x017D,   "BatAndCat" },
    { 0x017E,   "BluDotz Ltd" },
    { 0x017F,   "XTel Wireless ApS" },
    { 0x0180,   "Gigaset Communications GmbH" },
    { 0x0181,   "Gecko Health Innovations, Inc." },
    { 0x0182,   "HOP Ubiquitous" },
    { 0x0183,   "Walt Disney" },
    { 0x0184,   "Nectar" },
    { 0x0185,   "bel'apps LLC" },
    { 0x0186,   "CORE Lighting Ltd" },
    { 0x0187,   "Seraphim Sense Ltd" },
    { 0x0188,   "Unico RBC" },
    { 0x0189,   "Physical Enterprises Inc." },
    { 0x018A,   "Able Trend Technology Limited" },
    { 0x018B,   "Konica Minolta, Inc." },
    { 0x018C,   "Wilo SE" },
    { 0x018D,   "Extron Design Services" },
    { 0x018E,   "Fitbit, Inc." },
    { 0x018F,   "Fireflies Systems" },
    { 0x0190,   "Intelletto Technologies Inc." },
    { 0x0191,   "FDK CORPORATION" },
    { 0x0192,   "Cloudleaf, Inc" },
    { 0x0193,   "Maveric Automation LLC" },
    { 0x0194,   "Acoustic Stream Corporation" },
    { 0x0195,   "Zuli" },
    { 0x0196,   "Paxton Access Ltd" },
    { 0x0197,   "WiSilica Inc." },
    { 0x0198,   "VENGIT Korlatolt Felelossegu Tarsasag" },
    { 0x0199,   "SALTO SYSTEMS S.L." },
    { 0x019A,   "TRON Forum (formerly T-Engine Forum)" },
    { 0x019B,   "CUBETECH s.r.o." },
    { 0x019C,   "Cokiya Incorporated" },
    { 0x019D,   "CVS Health" },
    { 0x019E,   "Ceruus" },
    { 0x019F,   "Strainstall Ltd" },
    { 0x01A0,   "Channel Enterprises (HK) Ltd." },
    { 0x01A1,   "FIAMM" },
    { 0x01A2,   "GIGALANE.CO.,LTD" },
    { 0x01A3,   "EROAD" },
    { 0x01A4,   "Mine Safety Appliances" },
    { 0x01A5,   "Icon Health and Fitness" },
    { 0x01A6,   "Wille Engineering (formerly as Asandoo GmbH)" },
    { 0x01A7,   "ENERGOUS CORPORATION" },
    { 0x01A8,   "Taobao" },
    { 0x01A9,   "Canon Inc." },
    { 0x01AA,   "Geophysical Technology Inc." },
    { 0x01AB,   "Facebook, Inc." },
    { 0x01AC,   "Trividia Health, Inc." },
    { 0x01AD,   "FlightSafety International" },
    { 0x01AE,   "Earlens Corporation" },
    { 0x01AF,   "Sunrise Micro Devices, Inc." },
    { 0x01B0,   "Star Micronics Co., Ltd." },
    { 0x01B1,   "Netizens Sp. z o.o." },
    { 0x01B2,   "Nymi Inc." },
    { 0x01B3,   "Nytec, Inc." },
    { 0x01B4,   "Trineo Sp. z o.o." },
    { 0x01B5,   "Nest Labs Inc." },
    { 0x01B6,   "LM Technologies Ltd" },
    { 0x01B7,   "General Electric Company" },
    { 0x01B8,   "i+D3 S.L." },
    { 0x01B9,   "HANA Micron" },
    { 0x01BA,   "Stages Cycling LLC" },
    { 0x01BB,   "Cochlear Bone Anchored Solutions AB" },
    { 0x01BC,   "SenionLab AB" },
    { 0x01BD,   "Syszone Co., Ltd" },
    { 0x01BE,   "Pulsate Mobile Ltd." },
    { 0x01BF,   "Hong Kong HunterSun Electronic Limited" },
    { 0x01C0,   "pironex GmbH" },
    { 0x01C1,   "BRADATECH Corp." },
    { 0x01C2,   "Transenergooil AG" },
    { 0x01C3,   "Bunch" },
    { 0x01C4,   "DME Microelectronics" },
    { 0x01C5,   "Bitcraze AB" },
    { 0x01C6,   "HASWARE Inc." },
    { 0x01C7,   "Abiogenix Inc." },
    { 0x01C8,   "Poly-Control ApS" },
    { 0x01C9,   "Avi-on" },
    { 0x01CA,   "Laerdal Medical AS" },
    { 0x01CB,   "Fetch My Pet" },
    { 0x01CC,   "Sam Labs Ltd." },
    { 0x01CD,   "Chengdu Synwing Technology Ltd" },
    { 0x01CE,   "HOUWA SYSTEM DESIGN, k.k." },
    { 0x01CF,   "BSH" },
    { 0x01D0,   "Primus Inter Pares Ltd" },
    { 0x01D1,   "August Home, Inc" },
    { 0x01D2,   "Gill Electronics" },
    { 0x01D3,   "Sky Wave Design" },
    { 0x01D4,   "Newlab S.r.l." },
    { 0x01D5,   "ELAD srl" },
    { 0x01D6,   "G-wearables inc." },
    { 0x01D7,   "Squadrone Systems Inc." },
    { 0x01D8,   "Code Corporation" },
    { 0x01D9,   "Savant Systems LLC" },
    { 0x01DA,   "Logitech International SA" },
    { 0x01DB,   "Innblue Consulting" },
    { 0x01DC,   "iParking Ltd." },
    { 0x01DD,   "Koninklijke Philips Electronics N.V." },
    { 0x01DE,   "Minelab Electronics Pty Limited" },
    { 0x01DF,   "Bison Group Ltd." },
    { 0x01E0,   "Widex A/S" },
    { 0x01E1,   "Jolla Ltd" },
    { 0x01E2,   "Lectronix, Inc." },
    { 0x01E3,   "Caterpillar Inc" },
    { 0x01E4,   "Freedom Innovations" },
    { 0x01E5,   "Dynamic Devices Ltd" },
    { 0x01E6,   "Technology Solutions (UK) Ltd" },
    { 0x01E7,   "IPS Group Inc." },
    { 0x01E8,   "STIR" },
    { 0x01E9,   "Sano, Inc." },
    { 0x01EA,   "Advanced Application Design, Inc." },
    { 0x01EB,   "AutoMap LLC" },
    { 0x01EC,   "Spreadtrum Communications Shanghai Ltd" },
    { 0x01ED,   "CuteCircuit LTD" },
    { 0x01EE,   "Valeo Service" },
    { 0x01EF,   "Fullpower Technologies, Inc." },
    { 0x01F0,   "KloudNation" },
    { 0x01F1,   "Zebra Technologies Corporation" },
    { 0x01F2,   "Itron, Inc." },
    { 0x01F3,   "The University of Tokyo" },
    { 0x01F4,   "UTC Fire and Security" },
    { 0x01F5,   "Cool Webthings Limited" },
    { 0x01F6,   "DJO Global" },
    { 0x01F7,   "Gelliner Limited" },
    { 0x01F8,   "Anyka (Guangzhou) Microelectronics Technology Co, LTD" },
    { 0x01F9,   "Medtronic Inc." },
    { 0x01FA,   "Gozio Inc." },
    { 0x01FB,   "Form Lifting, LLC" },
    { 0x01FC,   "Wahoo Fitness, LLC" },
    { 0x01FD,   "Kontakt Micro-Location Sp. z o.o." },
    { 0x01FE,   "Radio Systems Corporation" },
    { 0x01FF,   "Freescale Semiconductor, Inc." },
    { 0x0200,   "Verifone Systems Pte Ltd. Taiwan Branch" },
    { 0x0201,   "AR Timing" },
    { 0x0202,   "Rigado LLC" },
    { 0x0203,   "Kemppi Oy" },
    { 0x0204,   "Tapcentive Inc." },
    { 0x0205,   "Smartbotics Inc." },
    { 0x0206,   "Otter Products, LLC" },
    { 0x0207,   "STEMP Inc." },
    { 0x0208,   "LumiGeek LLC" },
    { 0x0209,   "InvisionHeart Inc." },
    { 0x020A,   "Macnica Inc." },
    { 0x020B,   "Jaguar Land Rover Limited" },
    { 0x020C,   "CoroWare Technologies, Inc" },
    { 0x020D,   "Simplo Technology Co., LTD" },
    { 0x020E,   "Omron Healthcare Co., LTD" },
    { 0x020F,   "Comodule GMBH" },
    { 0x0210,   "ikeGPS" },
    { 0x0211,   "Telink Semiconductor Co. Ltd" },
    { 0x0212,   "Interplan Co., Ltd" },
    { 0x0213,   "Wyler AG" },
    { 0x0214,   "IK Multimedia Production srl" },
    { 0x0215,   "Lukoton Experience Oy" },
    { 0x0216,   "MTI Ltd" },
    { 0x0217,   "Tech4home, Lda" },
    { 0x0218,   "Hiotech AB" },
    { 0x0219,   "DOTT Limited" },
    { 0x021A,   "Blue Speck Labs, LLC" },
    { 0x021B,   "Cisco Systems, Inc" },
    { 0x021C,   "Mobicomm Inc" },
    { 0x021D,   "Edamic" },
    { 0x021E,   "Goodnet, Ltd" },
    { 0x021F,   "Luster Leaf Products Inc" },
    { 0x0220,   "Manus Machina BV" },
    { 0x0221,   "Mobiquity Networks Inc" },
    { 0x0222,   "Praxis Dynamics" },
    { 0x0223,   "Philip Morris Products S.A." },
    { 0x0224,   "Comarch SA" },
    { 0x0225,   "Nestl Nespresso S.A." },
    { 0x0226,   "Merlinia A/S" },
    { 0x0227,   "LifeBEAM Technologies" },
    { 0x0228,   "Twocanoes Labs, LLC" },
    { 0x0229,   "Muoverti Limited" },
    { 0x022A,   "Stamer Musikanlagen GMBH" },
    { 0x022B,   "Tesla Motors" },
    { 0x022C,   "Pharynks Corporation" },
    { 0x022D,   "Lupine" },
    { 0x022E,   "Siemens AG" },
    { 0x022F,   "Huami (Shanghai) Culture Communication CO., LTD" },
    { 0x0230,   "Foster Electric Company, Ltd" },
    { 0x0231,   "ETA SA" },
    { 0x0232,   "x-Senso Solutions Kft" },
    { 0x0233,   "Shenzhen SuLong Communication Ltd" },
    { 0x0234,   "FengFan (BeiJing) Technology Co, Ltd" },
    { 0x0235,   "Qrio Inc" },
    { 0x0236,   "Pitpatpet Ltd" },
    { 0x0237,   "MSHeli s.r.l." },
    { 0x0238,   "Trakm8 Ltd" },
    { 0x0239,   "JIN CO, Ltd" },
    { 0x023A,   "Alatech Tehnology" },
    { 0x023B,   "Beijing CarePulse Electronic Technology Co, Ltd" },
    { 0x023C,   "Awarepoint" },
    { 0x023D,   "ViCentra B.V." },
    { 0x023E,   "Raven Industries" },
    { 0x023F,   "WaveWare Technologies Inc." },
    { 0x0240,   "Argenox Technologies" },
    { 0x0241,   "Bragi GmbH" },
    { 0x0242,   "16Lab Inc" },
    { 0x0243,   "Masimo Corp" },
    { 0x0244,   "Iotera Inc" },
    { 0x0245,   "Endress+Hauser" },
    { 0x0246,   "ACKme Networks, Inc." },
    { 0x0247,   "FiftyThree Inc." },
    { 0x0248,   "Parker Hannifin Corp" },
    { 0x0249,   "Transcranial Ltd" },
    { 0x024A,   "Uwatec AG" },
    { 0x024B,   "Orlan LLC" },
    { 0x024C,   "Blue Clover Devices" },
    { 0x024D,   "M-Way Solutions GmbH" },
    { 0x024E,   "Microtronics Engineering GmbH" },
    { 0x024F,   "Schneider Schreibgerte GmbH" },
    { 0x0250,   "Sapphire Circuits LLC" },
    { 0x0251,   "Lumo Bodytech Inc." },
    { 0x0252,   "UKC Technosolution" },
    { 0x0253,   "Xicato Inc." },
    { 0x0254,   "Playbrush" },
    { 0x0255,   "Dai Nippon Printing Co., Ltd." },
    { 0x0256,   "G24 Power Limited" },
    { 0x0257,   "AdBabble Local Commerce Inc." },
    { 0x0258,   "Devialet SA" },
    { 0x0259,   "ALTYOR" },
    { 0x025A,   "University of Applied Sciences Valais/Haute Ecole Valaisanne" },
    { 0x025B,   "Five Interactive, LLC dba Zendo" },
    { 0x025C,   "NetEaseHangzhouNetwork co.Ltd." },
    { 0x025D,   "Lexmark International Inc." },
    { 0x025E,   "Fluke Corporation" },
    { 0x025F,   "Yardarm Technologies" },
    { 0x0260,   "SensaRx" },
    { 0x0261,   "SECVRE GmbH" },
    { 0x0262,   "Glacial Ridge Technologies" },
    { 0x0263,   "Identiv, Inc." },
    { 0x0264,   "DDS, Inc." },
    { 0x0265,   "SMK Corporation" },
    { 0x0266,   "Schawbel Technologies LLC" },
    { 0x0267,   "XMI Systems SA" },
    { 0x0268,   "Cerevo" },
    { 0x0269,   "Torrox GmbH & Co KG" },
    { 0x026A,   "Gemalto" },
    { 0x026B,   "DEKA Research & Development Corp." },
    { 0x026C,   "Domster Tadeusz Szydlowski" },
    { 0x026D,   "Technogym SPA" },
    { 0x026E,   "FLEURBAEY BVBA" },
    { 0x026F,   "Aptcode Solutions" },
    { 0x0270,   "LSI ADL Technology" },
    { 0x0271,   "Animas Corp" },
    { 0x0272,   "Alps Electric Co., Ltd." },
    { 0x0273,   "OCEASOFT" },
    { 0x0274,   "Motsai Research" },
    { 0x0275,   "Geotab" },
    { 0x0276,   "E.G.O. Elektro-Gertebau GmbH" },
    { 0x0277,   "bewhere inc" },
    { 0x0278,   "Johnson Outdoors Inc" },
    { 0x0279,   "steute Schaltgerate GmbH & Co. KG" },
    { 0x027A,   "Ekomini inc." },
    { 0x027B,   "DEFA AS" },
    { 0x027C,   "Aseptika Ltd" },
    { 0x027D,   "HUAWEI Technologies Co., Ltd. ( )" },
    { 0x027E,   "HabitAware, LLC" },
    { 0x027F,   "ruwido austria gmbh" },
    { 0x0280,   "ITEC corporation" },
    { 0x0281,   "StoneL" },
    { 0x0282,   "Sonova AG" },
    { 0x0283,   "Maven Machines, Inc." },
    { 0x0284,   "Synapse Electronics" },
    { 0x0285,   "Standard Innovation Inc." },
    { 0x0286,   "RF Code, Inc." },
    { 0x0287,   "Wally Ventures S.L." },
    { 0x0288,   "Willowbank Electronics Ltd" },
    { 0x0289,   "SK Telecom" },
    { 0x028A,   "Jetro AS" },
    { 0x028B,   "Code Gears LTD" },
    { 0x028C,   "NANOLINK APS" },
    { 0x028D,   "IF, LLC" },
    { 0x028E,   "RF Digital Corp" },
    { 0x028F,   "Church & Dwight Co., Inc" },
    { 0x0290,   "Multibit Oy" },
    { 0x0291,   "CliniCloud Inc" },
    { 0x0292,   "SwiftSensors" },
    { 0x0293,   "Blue Bite" },
    { 0x0294,   "ELIAS GmbH" },
    { 0x0295,   "Sivantos GmbH" },
    { 0x0296,   "Petzl" },
    { 0x0297,   "storm power ltd" },
    { 0x0298,   "EISST Ltd" },
    { 0x0299,   "Inexess Technology Simma KG" },
    { 0x029A,   "Currant, Inc." },
    { 0x029B,   "C2 Development, Inc." },
    { 0x029C,   "Blue Sky Scientific, LLC" },
    { 0x029D,   "ALOTTAZS LABS, LLC" },
    { 0x029E,   "Kupson spol. s r.o." },
    { 0x029F,   "Areus Engineering GmbH" },
    { 0x02A0,   "Impossible Camera GmbH" },
    { 0x02A1,   "InventureTrack Systems" },
    { 0x02A2,   "LockedUp" },
    { 0x02A3,   "Itude" },
    { 0x02A4,   "Pacific Lock Company" },
    { 0x02A5,   "Tendyron Corporation ( )" },
    { 0x02A6,   "Robert Bosch GmbH" },
    { 0x02A7,   "Illuxtron international B.V." },
    { 0x02A8,   "miSport Ltd." },
    { 0x02A9,   "Chargelib" },
    { 0x02AA,   "Doppler Lab" },
    { 0x02AB,   "BBPOS Limited" },
    { 0x02AC,   "RTB Elektronik GmbH & Co. KG" },
    { 0x02AD,   "Rx Networks, Inc." },
    { 0x02AE,   "WeatherFlow, Inc." },
    { 0x02AF,   "Technicolor USA Inc." },
    { 0x02B0,   "Bestechnic(Shanghai),Ltd" },
    { 0x02B1,   "Raden Inc" },
    { 0x02B2,   "JouZen Oy" },
    { 0x02B3,   "CLABER S.P.A." },
    { 0x02B4,   "Hyginex, Inc." },
    { 0x02B5,   "HANSHIN ELECTRIC RAILWAY CO.,LTD." },
    { 0x02B6,   "Schneider Electric" },
    { 0x02B7,   "Oort Technologies LLC" },
    { 0x02B8,   "Chrono Therapeutics" },
    { 0x02B9,   "Rinnai Corporation" },
    { 0x02BA,   "Swissprime Technologies AG" },
    { 0x02BB,   "Koha.,Co.Ltd" },
    { 0x02BC,   "Genevac Ltd" },
    { 0x02BD,   "Chemtronics" },
    { 0x02BE,   "Seguro Technology Sp. z o.o." },
    { 0x02BF,   "Redbird Flight Simulations" },
    { 0x02C0,   "Dash Robotics" },
    { 0x02C1,   "LINE Corporation" },
    { 0x02C2,   "Guillemot Corporation" },
    { 0x02C3,   "Techtronic Power Tools Technology Limited" },
    { 0x02C4,   "Wilson Sporting Goods" },
    { 0x02C5,   "Lenovo (Singapore) Pte Ltd. ( )" },
    { 0x02C6,   "Ayatan Sensors" },
    { 0x02C7,   "Electronics Tomorrow Limited" },
    { 0x02C8,   "VASCO Data Security International, Inc." },
    { 0x02C9,   "PayRange Inc." },
    { 0x02CA,   "ABOV Semiconductor" },
    { 0x02CB,   "AINA-Wireless Inc." },
    { 0x02CC,   "Eijkelkamp Soil & Water" },
    { 0x02CD,   "BMA ergonomics b.v." },
    { 0x02CE,   "Teva Branded Pharmaceutical Products R&D, Inc." },
    { 0x02CF,   "Anima" },
    { 0x02D0,   "3M" },
    { 0x02D1,   "Empatica Srl" },
    { 0x02D2,   "Afero, Inc." },
    { 0x02D3,   "Powercast Corporation" },
    { 0x02D4,   "Secuyou ApS" },
    { 0x02D5,   "OMRON Corporation" },
    { 0x02D6,   "Send Solutions" },
    { 0x02D7,   "NIPPON SYSTEMWARE CO.,LTD." },
    { 0x02D8,   "Neosfar" },
    { 0x02D9,   "Fliegl Agrartechnik GmbH" },
    { 0x02DA,   "Gilvader" },
    { 0x02DB,   "Digi International Inc (R)" },
    { 0x02DC,   "DeWalch Technologies, Inc." },
    { 0x02DD,   "Flint Rehabilitation Devices, LLC" },
    { 0x02DE,   "Samsung SDS Co., Ltd." },
    { 0x02DF,   "Blur Product Development" },
    { 0x02E0,   "University of Michigan" },
    { 0x02E1,   "Victron Energy BV" },
    { 0x02E2,   "NTT docomo" },
    { 0x02E3,   "Carmanah Technologies Corp." },
    { 0x02E4,   "Bytestorm Ltd." },
    { 0x02E5,   "Espressif Incorporated ( () )" },
    { 0x02E6,   "Unwire" },
    { 0x02E7,   "Connected Yard, Inc." },
    { 0x02E8,   "American Music Environments" },
    { 0x02E9,   "Sensogram Technologies, Inc." },
    { 0x02EA,   "Fujitsu Limited" },
    { 0x02EB,   "Ardic Technology" },
    { 0x02EC,   "Delta Systems, Inc" },
    { 0x02ED,   "HTC Corporation" },
    { 0x02EE,   "Citizen Holdings Co., Ltd." },
    { 0x02EF,   "SMART-INNOVATION.inc" },
    { 0x02F0,   "Blackrat Software" },
    { 0x02F1,   "The Idea Cave, LLC" },
    { 0x02F2,   "GoPro, Inc." },
    { 0x02F3,   "AuthAir, Inc" },
    { 0x02F4,   "Vensi, Inc." },
    { 0x02F5,   "Indagem Tech LLC" },
    { 0x02F6,   "Intemo Technologies" },
    { 0x02F7,   "DreamVisions co., Ltd." },
    { 0x02F8,   "Runteq Oy Ltd" },
    { 0x02F9,   "IMAGINATION TECHNOLOGIES LTD" },
    { 0x02FA,   "CoSTAR TEchnologies" },
    { 0x02FB,   "Clarius Mobile Health Corp." },
    { 0x02FC,   "Shanghai Frequen Microelectronics Co., Ltd." },
    { 0x02FD,   "Uwanna, Inc." },
    { 0x02FE,   "Lierda Science & Technology Group Co., Ltd." },
    { 0x02FF,   "Silicon Laboratories" },
    { 0x0300,   "World Moto Inc." },
    { 0x0301,   "Giatec Scientific Inc." },
    { 0x0302,   "Loop Devices, Inc" },
    { 0x0303,   "IACA electronique" },
    { 0x0304,   "Proxy Technologies, Inc." },
    { 0x0305,   "Swipp ApS" },
    { 0x0306,   "Life Laboratory Inc." },
    { 0x0307,   "FUJI INDUSTRIAL CO.,LTD." },
    { 0x0308,   "Surefire, LLC" },
    { 0x0309,   "Dolby Labs" },
    { 0x030A,   "Ellisys" },
    { 0x030B,   "Magnitude Lighting Converters" },
    { 0x030C,   "Hilti AG" },
    { 0x030D,   "Devdata S.r.l." },
    { 0x030E,   "Deviceworx" },
    { 0x030F,   "Shortcut Labs" },
    { 0x0310,   "SGL Italia S.r.l." },
    { 0x0311,   "PEEQ DATA" },
    { 0x0312,   "Ducere Technologies Pvt Ltd" },
    { 0x0313,   "DiveNav, Inc." },
    { 0x0314,   "RIIG AI Sp. z o.o." },
    { 0x0315,   "Thermo Fisher Scientific" },
    { 0x0316,   "AG Measurematics Pvt. Ltd." },
    { 0x0317,   "CHUO Electronics CO., LTD." },
    { 0x0318,   "Aspenta International" },
    { 0x0319,   "Eugster Frismag AG" },
    { 0x031A,   "Amber wireless GmbH" },
    { 0x031B,   "HQ Inc" },
    { 0x031C,   "Lab Sensor Solutions" },
    { 0x031D,   "Enterlab ApS" },
    { 0x031E,   "Eyefi, Inc." },
    { 0x031F,   "MetaSystem S.p.A." },
    { 0x0320,   "SONO ELECTRONICS. CO., LTD" },
    { 0x0321,   "Jewelbots" },
    { 0x0322,   "Compumedics Limited" },
    { 0x0323,   "Rotor Bike Components" },
    { 0x0324,   "Astro, Inc." },
    { 0x0325,   "Amotus Solutions" },
    { 0x0326,   "Healthwear Technologies (Changzhou)Ltd" },
    { 0x0327,   "Essex Electronics" },
    { 0x0328,   "Grundfos A/S" },
    { 0x0329,   "Eargo, Inc." },
    { 0x032A,   "Electronic Design Lab" },
    { 0x032B,   "ESYLUX" },
    { 0x032C,   "NIPPON SMT.CO.,Ltd" },
    { 0x032D,   "BM innovations GmbH" },
    { 0x032E,   "indoormap" },
    { 0x032F,   "OttoQ Inc" },
    { 0x0330,   "North Pole Engineering" },
    { 0x0331,   "3flares Technologies Inc." },
    { 0x0332,   "Electrocompaniet A.S." },
    { 0x0333,   "Mul-T-Lock" },
    { 0x0334,   "Corentium AS" },
    { 0x0335,   "Enlighted Inc" },
    { 0x0336,   "GISTIC" },
    { 0x0337,   "AJP2 Holdings, LLC" },
    { 0x0338,   "COBI GmbH" },
    { 0x0339,   "Blue Sky Scientific, LLC" },
    { 0x033A,   "Appception, Inc." },
    { 0x033B,   "Courtney Thorne Limited" },
    { 0x033C,   "Virtuosys" },
    { 0x033D,   "TPV Technology Limited" },
    { 0x033E,   "Monitra SA" },
    { 0x033F,   "Automation Components, Inc." },
    { 0x0340,   "Letsense s.r.l." },
    { 0x0341,   "Etesian Technologies LLC" },
    { 0x0342,   "GERTEC BRASIL LTDA." },
    { 0x0343,   "Drekker Development Pty. Ltd." },
    { 0x0344,   "Whirl Inc" },
    { 0x0345,   "Locus Positioning" },
    { 0x0346,   "Acuity Brands Lighting, Inc" },
    { 0x0347,   "Prevent Biometrics" },
    { 0x0348,   "Arioneo" },
    { 0x0349,   "VersaMe" },
    { 0x034A,   "Vaddio" },
    { 0x034B,   "Libratone A/S" },
    { 0x034C,   "HM Electronics, Inc." },
    { 0x034D,   "TASER International, Inc." },
    { 0x034E,   "SafeTrust Inc." },
    { 0x034F,   "Heartland Payment Systems" },
    { 0x0350,   "Bitstrata Systems Inc." },
    { 0x0351,   "Pieps GmbH" },
    { 0x0352,   "iRiding(Xiamen)Technology Co.,Ltd." },
    { 0x0353,   "Alpha Audiotronics, Inc." },
    { 0x0354,   "TOPPAN FORMS CO.,LTD." },
    { 0x0355,   "Sigma Designs, Inc." },
    { 0x0356,   "Spectrum Brands, Inc." },
    { 0x0357,   "Polymap Wireless" },
    { 0x0358,   "MagniWare Ltd." },
    { 0x0359,   "Novotec Medical GmbH" },
    { 0x035A,   "Medicom Innovation Partner a/s" },
    { 0x035B,   "Matrix Inc." },
    { 0x035C,   "Eaton Corporation" },
    { 0x035D,   "KYS" },
    { 0x035E,   "Naya Health, Inc." },
    { 0x035F,   "Acromag" },
    { 0x0360,   "Insulet Corporation" },
    { 0x0361,   "Wellinks Inc." },
    { 0x0362,   "ON Semiconductor" },
    { 0x0363,   "FREELAP SA" },
    { 0x0364,   "Favero Electronics Srl" },
    { 0x0365,   "BioMech Sensor LLC" },
    { 0x0366,   "BOLTT Sports technologies Private limited" },
    { 0x0367,   "Saphe International" },
    { 0x0368,   "Metormote AB" },
    { 0x0369,   "littleBits" },
    { 0x036A,   "SetPoint Medical" },
    { 0x036B,   "BRControls Products BV" },
    { 0x036C,   "Zipcar" },
    { 0x036D,   "AirBolt Pty Ltd" },
    { 0x036E,   "KeepTruckin Inc" },
    { 0x036F,   "Motiv, Inc." },
    { 0x0370,   "Wazombi Labs O" },
    { 0x0371,   "ORBCOMM" },
    { 0x0372,   "Nixie Labs, Inc." },
    { 0x0373,   "AppNearMe Ltd" },
    { 0x0374,   "Holman Industries" },
    { 0x0375,   "Expain AS" },
    { 0x0376,   "Electronic Temperature Instruments Ltd" },
    { 0x0377,   "Plejd AB" },
    { 0x0378,   "Propeller Health" },
    { 0x0379,   "Shenzhen iMCO Electronic Technology Co.,Ltd" },
    { 0x037A,   "Algoria" },
    { 0x037B,   "Apption Labs Inc." },
    { 0x037C,   "Cronologics Corporation" },
    { 0x037D,   "MICRODIA Ltd." },
    { 0x037E,   "lulabytes S.L." },
    { 0x037F,   "Nestec S.A." },
    { 0x0380,   "LLC \"MEGA-F service\"" },
    { 0x0381,   "Sharp Corporation" },
    { 0x0382,   "Precision Outcomes Ltd" },
    { 0x0383,   "Kronos Incorporated" },
    { 0x0384,   "OCOSMOS Co., Ltd." },
    { 0x0385,   "Embedded Electronic Solutions Ltd. dba e2Solutions" },
    { 0x0386,   "Aterica Inc." },
    { 0x0387,   "BluStor PMC, Inc." },
    { 0x0388,   "Kapsch TrafficCom AB" },
    { 0x0389,   "ActiveBlu Corporation" },
    { 0x038A,   "Kohler Mira Limited" },
    { 0x038B,   "Noke" },
    { 0x038C,   "Appion Inc." },
    { 0x038D,   "Resmed Ltd" },
    { 0x038E,   "Crownstone B.V." },
    { 0x038F,   "Xiaomi Inc." },
    { 0x0390,   "INFOTECH s.r.o." },
    { 0x0391,   "Thingsquare AB" },
    { 0x0392,   "T&D" },
    { 0x0393,   "LAVAZZA S.p.A." },
    { 0x0394,   "Netclearance Systems, Inc." },
    { 0x0395,   "SDATAWAY" },
    { 0x0396,   "BLOKS GmbH" },
    { 0x0397,   "LEGO System A/S" },
    { 0x0398,   "Thetatronics Ltd" },
    { 0x0399,   "Nikon Corporation" },
    { 0x039A,   "NeST" },
    { 0x039B,   "South Silicon Valley Microelectronics" },
    { 0x039C,   "ALE International" },
    { 0x039D,   "CareView Communications, Inc." },
    { 0x039E,   "SchoolBoard Limited" },
    { 0x039F,   "Molex Corporation" },
    { 0x03A0,   "IVT Wireless Limited" },
    { 0x03A1,   "Alpine Labs LLC" },
    { 0x03A2,   "Candura Instruments" },
    { 0x03A3,   "SmartMovt Technology Co., Ltd" },
    { 0x03A4,   "Token Zero Ltd" },
    { 0x03A5,   "ACE CAD Enterprise Co., Ltd. (ACECAD)" },
    { 0x03A6,   "Medela, Inc" },
    { 0x03A7,   "AeroScout" },
    { 0x03A8,   "Esrille Inc." },
    { 0x03A9,   "THINKERLY SRL" },
    { 0x03AA,   "Exon Sp. z o.o." },
    { 0x03AB,   "Meizu Technology Co., Ltd." },
    { 0x03AC,   "Smablo LTD" },
    { 0x03AD,   "XiQ" },
    { 0x03AE,   "Allswell Inc." },
    { 0x03AF,   "Comm-N-Sense Corp DBA Verigo" },
    { 0x03B0,   "VIBRADORM GmbH" },
    { 0x03B1,   "Otodata Wireless Network Inc." },
    { 0x03B2,   "Propagation Systems Limited" },
    { 0x03B3,   "Midwest Instruments & Controls" },
    { 0x03B4,   "Alpha Nodus, inc." },
    { 0x03B5,   "petPOMM, Inc" },
    { 0x03B6,   "Mattel" },
    { 0x03B7,   "Airbly Inc." },
    { 0x03B8,   "A-Safe Limited" },
    { 0x03B9,   "FREDERIQUE CONSTANT SA" },
    { 0x03BA,   "Maxscend Microelectronics Company Limited" },
    { 0x03BB,   "Abbott Diabetes Care" },
    { 0x03BC,   "ASB Bank Ltd" },
    { 0x03BD,   "amadas" },
    { 0x03BE,   "Applied Science, Inc." },
    { 0x03BF,   "iLumi Solutions Inc." },
    { 0x03C0,   "Arch Systems Inc." },
    { 0x03C1,   "Ember Technologies, Inc." },
    { 0x03C2,   "Snapchat Inc" },
    { 0x03C3,   "Casambi Technologies Oy" },
    { 0x03C4,   "Pico Technology Inc." },
    { 0x03C5,   "St. Jude Medical, Inc." },
    { 0x03C6,   "Intricon" },
    { 0x03C7,   "Structural Health Systems, Inc." },
    { 0x03C8,   "Avvel International" },
    { 0x03C9,   "Gallagher Group" },
    { 0x03CA,   "In2things Automation Pvt. Ltd." },
    { 0x03CB,   "SYSDEV Srl" },
    { 0x03CC,   "Vonkil Technologies Ltd" },
    { 0x03CD,   "Wynd Technologies, Inc." },
    { 0x03CE,   "CONTRINEX S.A." },
    { 0x03CF,   "MIRA, Inc." },
    { 0x03D0,   "Watteam Ltd" },
    { 0x03D1,   "Density Inc." },
    { 0x03D2,   "IOT Pot India Private Limited" },
    { 0x03D3,   "Sigma Connectivity AB" },
    { 0x03D4,   "PEG PEREGO SPA" },
    { 0x03D5,   "Wyzelink Systems Inc." },
    { 0x03D6,   "Yota Devices LTD" },
    { 0x03D7,   "FINSECUR" },
    { 0x03D8,   "Zen-Me Labs Ltd" },
    { 0x03D9,   "3IWare Co., Ltd." },
    { 0x03DA,   "EnOcean GmbH" },
    { 0x03DB,   "Instabeat, Inc" },
    { 0x03DC,   "Nima Labs" },
    { 0x03DD,   "Andreas Stihl AG & Co. KG" },
    { 0x03DE,   "Nathan Rhoades LLC" },
    { 0x03DF,   "Grob Technologies, LLC" },
    { 0x03E0,   "Actions (Zhuhai) Technology Co., Limited" },
    { 0x03E1,   "SPD Development Company Ltd" },
    { 0x03E2,   "Sensoan Oy" },
    { 0x03E3,   "Qualcomm Life Inc" },
    { 0x03E4,   "Chip-ing AG" },
    { 0x03E5,   "ffly4u" },
    { 0x03E6,   "IoT Instruments Oy" },
    { 0x03E7,   "TRUE Fitness Technology" },
    { 0x03E8,   "Reiner Kartengeraete GmbH & Co. KG." },
    { 0x03E9,   "SHENZHEN LEMONJOY TECHNOLOGY CO., LTD." },
    { 0x03EA,   "Hello Inc." },
    { 0x03EB,   "Evollve Inc." },
    { 0x03EC,   "Jigowatts Inc." },
    { 0x03ED,   "BASIC MICRO.COM,INC." },
    { 0x03EE,   "CUBE TECHNOLOGIES" },
    { 0x03EF,   "foolography GmbH" },
    { 0x03F0,   "CLINK" },
    { 0x03F1,   "Hestan Smart Cooking Inc." },
    { 0x03F2,   "WindowMaster A/S" },
    { 0x03F3,   "Flowscape AB" },
    { 0x03F4,   "PAL Technologies Ltd" },
    { 0x03F5,   "WHERE, Inc." },
    { 0x03F6,   "Iton Technology Corp." },
    { 0x03F7,   "Owl Labs Inc." },
    { 0x03F8,   "Rockford Corp." },
    { 0x03F9,   "Becon Technologies Co.,Ltd." },
    { 0x03FA,   "Vyassoft Technologies Inc" },
    { 0x03FB,   "Nox Medical" },
    { 0x03FC,   "Kimberly-Clark" },
    { 0x03FD,   "Trimble Navigation Ltd." },
    { 0x03FE,   "Littelfuse" },
    { 0x03FF,   "Withings" },
    { 0x0400,   "i-developer IT Beratung UG" },
    { 0x0401,   "" },
    { 0x0402,   "Sears Holdings Corporation" },
    { 0x0403,   "Gantner Electronic GmbH" },
    { 0x0404,   "Authomate Inc" },
    { 0x0405,   "Vertex International, Inc." },
    { 0x0406,   "Airtago" },
    { 0x0407,   "Swiss Audio SA" },
    { 0x0408,   "ToGetHome Inc." },
    { 0x0409,   "AXIS" },
    { 0x040A,   "Openmatics" },
    { 0x040B,   "Jana Care Inc." },
    { 0x040C,   "Senix Corporation" },
    { 0x040D,   "NorthStar Battery Company, LLC" },
    { 0x040E,   "SKF (U.K.) Limited" },
    { 0x040F,   "CO-AX Technology, Inc." },
    { 0x0410,   "Fender Musical Instruments" },
    { 0x0411,   "Luidia Inc" },
    { 0x0412,   "SEFAM" },
    { 0x0413,   "Wireless Cables Inc" },
    { 0x0414,   "Lightning Protection International Pty Ltd" },
    { 0x0415,   "Uber Technologies Inc" },
    { 0x0416,   "SODA GmbH" },
    { 0x0417,   "Fatigue Science" },
    { 0x0418,   "Alpine Electronics Inc." },
    { 0x0419,   "Novalogy LTD" },
    { 0x041A,   "Friday Labs Limited" },
    { 0x041B,   "OrthoAccel Technologies" },
    { 0x041C,   "WaterGuru, Inc." },
    { 0x041D,   "Benning Elektrotechnik und Elektronik GmbH & Co. KG" },
    { 0x041E,   "Dell Computer Corporation" },
    { 0x041F,   "Kopin Corporation" },
    { 0x0420,   "TecBakery GmbH" },
    { 0x0421,   "Backbone Labs, Inc." },
    { 0x0422,   "DELSEY SA" },
    { 0x0423,   "Chargifi Limited" },
    { 0x0424,   "Trainesense Ltd." },
    { 0x0425,   "Unify Software and Solutions GmbH & Co. KG" },
    { 0x0426,   "Husqvarna AB" },
    { 0x0427,   "Focus fleet and fuel management inc" },
    { 0x0428,   "SmallLoop, LLC" },
    { 0x0429,   "Prolon Inc." },
    { 0x042A,   "BD Medical" },
    { 0x042B,   "iMicroMed Incorporated" },
    { 0x042C,   "Ticto N.V." },
    { 0x042D,   "Meshtech AS" },
    { 0x042E,   "MemCachier Inc." },
    { 0x042F,   "Danfoss A/S" },
    { 0x0430,   "SnapStyk Inc." },
    { 0x0431,   "Amway Corporation" },
    { 0x0432,   "Silk Labs, Inc." },
    { 0x0433,   "Pillsy Inc." },
    { 0x0434,   "Hatch Baby, Inc." },
    { 0x0435,   "Blocks Wearables Ltd." },
    { 0x0436,   "Drayson Technologies (Europe) Limited" },
    { 0x0437,   "eBest IOT Inc." },
    { 0x0438,   "Helvar Ltd" },
    { 0x0439,   "Radiance Technologies" },
    { 0x043A,   "Nuheara Limited" },
    { 0x043B,   "Appside co., ltd." },
    { 0x043C,   "DeLaval" },
    { 0x043D,   "Coiler Corporation" },
    { 0x043E,   "Thermomedics, Inc." },
    { 0x043F,   "Tentacle Sync GmbH" },
    { 0x0440,   "Valencell, Inc." },
    { 0x0441,   "iProtoXi Oy" },
    { 0x0442,   "SECOM CO., LTD." },
    { 0x0443,   "Tucker International LLC" },
    { 0x0444,   "Metanate Limited" },
    { 0x0445,   "Kobian Canada Inc." },
    { 0x0446,   "NETGEAR, Inc." },
    { 0x0447,   "Fabtronics Australia Pty Ltd" },
    { 0x0448,   "Grand Centrix GmbH" },
    { 0x0449,   "1UP USA.com llc" },
    { 0x044A,   "SHIMANO INC." },
    { 0x044B,   "Nain Inc." },
    { 0x044C,   "LifeStyle Lock, LLC" },
    { 0x044D,   "VEGA Grieshaber KG" },
    { 0x044E,   "Xtrava Inc." },
    { 0x044F,   "TTS Tooltechnic Systems AG & Co. KG" },
    { 0x0450,   "Teenage Engineering AB" },
    { 0x0451,   "Tunstall Nordic AB" },
    { 0x0452,   "Svep Design Center AB" },
    { 0x0453,   "GreenPeak Technologies BV" },
    { 0x0454,   "Sphinx Electronics GmbH & Co KG" },
    { 0x0455,   "Atomation" },
    { 0x0456,   "Nemik Consulting Inc" },
    { 0x0457,   "RF INNOVATION" },
    { 0x0458,   "Mini Solution Co., Ltd." },
    { 0x0459,   "Lumenetix, Inc" },
    { 0x045A,   "2048450 Ontario Inc" },
    { 0x045B,   "SPACEEK LTD" },
    { 0x045C,   "Delta T Corporation" },
    { 0x045D,   "Boston Scientific Corporation" },
    { 0x045E,   "Nuviz, Inc." },
    { 0x045F,   "Real Time Automation, Inc." },
    { 0x0460,   "Kolibree" },
    { 0x0461,   "vhf elektronik GmbH" },
    { 0x0462,   "Bonsai Systems GmbH" },
    { 0x0463,   "Fathom Systems Inc." },
    { 0x0464,   "Bellman & Symfon" },
    { 0x0465,   "International Forte Group LLC" },
    { 0x0466,   "CycleLabs Solutions inc." },
    { 0x0467,   "Codenex Oy" },
    { 0x0468,   "Kynesim Ltd" },
    { 0x0469,   "Palago AB" },
    { 0x046A,   "INSIGMA INC." },
    { 0x046B,   "PMD Solutions" },
    { 0x046C,   "Qingdao Realtime Technology Co., Ltd." },
    { 0x046D,   "BEGA Gantenbrink-Leuchten KG" },
    { 0x046E,   "Pambor Ltd." },
    { 0x046F,   "Develco Products A/S" },
    { 0x0470,   "iDesign s.r.l." },
    { 0x0471,   "TiVo Corp" },
    { 0x0472,   "Control-J Pty Ltd" },
    { 0x0473,   "Steelcase, Inc." },
    { 0x0474,   "iApartment co., ltd." },
    { 0x0475,   "Icom inc." },
    { 0x0476,   "Oxstren Wearable Technologies Private Limited" },
    { 0x0477,   "Blue Spark Technologies" },
    { 0x0478,   "FarSite Communications Limited" },
    { 0x0479,   "mywerk system GmbH" },
    { 0x047A,   "Sinosun Technology Co., Ltd." },
    { 0x047B,   "MIYOSHI ELECTRONICS CORPORATION" },
    { 0x047C,   "POWERMAT LTD" },
    { 0x047D,   "Occly LLC" },
    { 0x047E,   "OurHub Dev IvS" },
    { 0x047F,   "Pro-Mark, Inc." },
    { 0x0480,   "Dynometrics Inc." },
    { 0x0481,   "Quintrax Limited" },
    { 0x0482,   "POS Tuning Udo Vosshenrich GmbH & Co. KG" },
    { 0x0483,   "Multi Care Systems B.V." },
    { 0x0484,   "Revol Technologies Inc" },
    { 0x0485,   "SKIDATA AG" },
    { 0x0486,   "DEV TECNOLOGIA INDUSTRIA, COMERCIO E MANUTENCAO DE EQUIPAMENTOS LTDA. - ME" },
    { 0x0487,   "Centrica Connected Home" },
    { 0x0488,   "Automotive Data Solutions Inc" },
    { 0x0489,   "Igarashi Engineering" },
    { 0x048A,   "Taelek Oy" },
    { 0x048B,   "CP Electronics Limited" },
    { 0x048C,   "Vectronix AG" },
    { 0x048D,   "S-Labs Sp. z o.o." },
    { 0x048E,   "Companion Medical, Inc." },
    { 0x048F,   "BlueKitchen GmbH" },
    { 0x0490,   "Matting AB" },
    { 0x0491,   "SOREX - Wireless Solutions GmbH" },
    { 0x0492,   "ADC Technology, Inc." },
    { 0x0493,   "Lynxemi Pte Ltd" },
    { 0x0494,   "SENNHEISER electronic GmbH & Co. KG" },
    { 0x0495,   "LMT Mercer Group, Inc" },
    { 0x0496,   "Polymorphic Labs LLC" },
    { 0x0497,   "Cochlear Limited" },
    { 0x0498,   "METER Group, Inc. USA" },
    { 0x0499,   "Ruuvi Innovations Ltd." },
    { 0x049A,   "Situne AS" },
    { 0x049B,   "nVisti, LLC" },
    { 0x049C,   "DyOcean" },
    { 0x049D,   "Uhlmann & Zacher GmbH" },
    { 0x049E,   "AND!XOR LLC" },
    { 0x049F,   "tictote AB" },
    { 0x04A0,   "Vypin, LLC" },
    { 0x04A1,   "PNI Sensor Corporation" },
    { 0x04A2,   "ovrEngineered, LLC" },
    { 0x04A3,   "GT-tronics HK Ltd" },
    { 0x04A4,   "Herbert Waldmann GmbH & Co. KG" },
    { 0x04A5,   "Guangzhou FiiO Electronics Technology Co.,Ltd" },
    { 0x04A6,   "Vinetech Co., Ltd" },
    { 0x04A7,   "Dallas Logic Corporation" },
    { 0x04A8,   "BioTex, Inc." },
    { 0x04A9,   "DISCOVERY SOUND TECHNOLOGY, LLC" },
    { 0x04AA,   "LINKIO SAS" },
    { 0x04AB,   "Harbortronics, Inc." },
    { 0x04AC,   "Undagrid B.V." },
    { 0x04AD,   "Shure Inc" },
    { 0x04AE,   "ERM Electronic Systems LTD" },
    { 0x04AF,   "BIOROWER Handelsagentur GmbH" },
    { 0x04B0,   "Weba Sport und Med. Artikel GmbH" },
    { 0x04B1,   "Kartographers Technologies Pvt. Ltd." },
    { 0x04B2,   "The Shadow on the Moon" },
    { 0x04B3,   "mobike (Hong Kong) Limited" },
    { 0x04B4,   "Inuheat Group AB" },
    { 0x04B5,   "Swiftronix AB" },
    { 0x04B6,   "Diagnoptics Technologies" },
    { 0x04B7,   "Analog Devices, Inc." },
    { 0x04B8,   "Soraa Inc." },
    { 0x04B9,   "CSR Building Products Limited" },
    { 0x04BA,   "Crestron Electronics, Inc." },
    { 0x04BB,   "Neatebox Ltd" },
    { 0x04BC,   "Draegerwerk AG & Co. KGaA" },
    { 0x04BD,   "AlbynMedical" },
    { 0x04BE,   "Averos FZCO" },
    { 0x04BF,   "VIT Initiative, LLC" },
    { 0x04C0,   "Statsports International" },
    { 0x04C1,   "Sospitas, s.r.o." },
    { 0x04C2,   "Dmet Products Corp." },
    { 0x04C3,   "Mantracourt Electronics Limited" },
    { 0x04C4,   "TeAM Hutchins AB" },
    { 0x04C5,   "Seibert Williams Glass, LLC" },
    { 0x04C6,   "Insta GmbH" },
    { 0x04C7,   "Svantek Sp. z o.o." },
    { 0x04C8,   "Shanghai Flyco Electrical Appliance Co., Ltd." },
    { 0x04C9,   "Thornwave Labs Inc" },
    { 0x04CA,   "Steiner-Optik GmbH" },
    { 0x04CB,   "Novo Nordisk A/S" },
    { 0x04CC,   "Enflux Inc." },
    { 0x04CD,   "Safetech Products LLC" },
    { 0x04CE,   "GOOOLED S.R.L." },
    { 0x04CF,   "DOM Sicherheitstechnik GmbH & Co. KG" },
    { 0x04D0,   "Olympus Corporation" },
    { 0x04D1,   "KTS GmbH" },
    { 0x04D2,   "Anloq Technologies Inc." },
    { 0x04D3,   "Queercon, Inc" },
    { 0x04D4,   "5th Element Ltd" },
    { 0x04D5,   "Gooee Limited" },
    { 0x04D6,   "LUGLOC LLC" },
    { 0x04D7,   "Blincam, Inc." },
    { 0x04D8,   "FUJIFILM Corporation" },
    { 0x04D9,   "RandMcNally" },
    { 0x04DA,   "Franceschi Marina snc" },
    { 0x04DB,   "Engineered Audio, LLC." },
    { 0x04DC,   "IOTTIVE (OPC) PRIVATE LIMITED" },
    { 0x04DD,   "4MOD Technology" },
    { 0x04DE,   "Lutron Electronics Co., Inc." },
    { 0x04DF,   "Emerson" },
    { 0x04E0,   "Guardtec, Inc." },
    { 0x04E1,   "REACTEC LIMITED" },
    { 0x04E2,   "EllieGrid" },
    { 0x04E3,   "Under Armour" },
    { 0x04E4,   "Woodenshark" },
    { 0x04E5,   "Avack Oy" },
    { 0x04E6,   "Smart Solution Technology, Inc." },
    { 0x04E7,   "REHABTRONICS INC." },
    { 0x04E8,   "STABILO International" },
    { 0x04E9,   "Busch Jaeger Elektro GmbH" },
    { 0x04EA,   "Pacific Bioscience Laboratories, Inc" },
    { 0x04EB,   "Bird Home Automation GmbH" },
    { 0x04EC,   "Motorola Solutions" },
    { 0x04ED,   "R9 Technology, Inc." },
    { 0x04EE,   "Auxivia" },
    { 0x04EF,   "DaisyWorks, Inc" },
    { 0x04F0,   "Kosi Limited" },
    { 0x04F1,   "Theben AG" },
    { 0x04F2,   "InDreamer Techsol Private Limited" },
    { 0x04F3,   "Cerevast Medical" },
    { 0x04F4,   "ZanCompute Inc." },
    { 0x04F5,   "Pirelli Tyre S.P.A." },
    { 0x04F6,   "McLear Limited" },
    { 0x04F7,   "Shenzhen Huiding Technology Co.,Ltd." },
    { 0x04F8,   "Convergence Systems Limited" },
    { 0x04F9,   "Interactio" },
    { 0x04FA,   "Androtec GmbH" },
    { 0x04FB,   "Benchmark Drives GmbH & Co. KG" },
    { 0x04FC,   "SwingLync L. L. C." },
    { 0x04FD,   "Tapkey GmbH" },
    { 0x04FE,   "Woosim Systems Inc." },
    { 0x04FF,   "Microsemi Corporation" },
    { 0x0500,   "Wiliot LTD." },
    { 0x0501,   "Polaris IND" },
    { 0x0502,   "Specifi-Kali LLC" },
    { 0x0503,   "Locoroll, Inc" },
    { 0x0504,   "PHYPLUS Inc" },
    { 0x0505,   "Inplay Technologies LLC" },
    { 0x0506,   "Hager" },
    { 0x0507,   "Yellowcog" },
    { 0x0508,   "Axes System sp. z o. o." },
    { 0x0509,   "myLIFTER Inc." },
    { 0x050A,   "Shake-on B.V." },
    { 0x050B,   "Vibrissa Inc." },
    { 0x050C,   "OSRAM GmbH" },
    { 0x050D,   "TRSystems GmbH" },
    { 0x050E,   "Yichip Microelectronics (Hangzhou) Co.,Ltd." },
    { 0x050F,   "Foundation Engineering LLC" },
    { 0x0510,   "UNI-ELECTRONICS, INC." },
    { 0x0511,   "Brookfield Equinox LLC" },
    { 0x0512,   "Soprod SA" },
    { 0x0513,   "9974091 Canada Inc." },
    { 0x0514,   "FIBRO GmbH" },
    { 0x0515,   "RB Controls Co., Ltd." },
    { 0x0516,   "Footmarks" },
    { 0x0517,   "Amtronic Sverige AB (formerly Amcore AB)" },
    { 0x0518,   "MAMORIO.inc" },
    { 0x0519,   "Tyto Life LLC" },
    { 0x051A,   "Leica Camera AG" },
    { 0x051B,   "Angee Technologies Ltd." },
    { 0x051C,   "EDPS" },
    { 0x051D,   "OFF Line Co., Ltd." },
    { 0x051E,   "Detect Blue Limited" },
    { 0x051F,   "Setec Pty Ltd" },
    { 0x0520,   "Target Corporation" },
    { 0x0521,   "IAI Corporation" },
    { 0x0522,   "NS Tech, Inc." },
    { 0x0523,   "MTG Co., Ltd." },
    { 0x0524,   "Hangzhou iMagic Technology Co., Ltd" },
    { 0x0525,   "HONGKONG NANO IC TECHNOLOGIES CO., LIMITED" },
    { 0x0526,   "Honeywell International Inc." },
    { 0x0527,   "Albrecht JUNG" },
    { 0x0528,   "Lunera Lighting Inc." },
    { 0x0529,   "Lumen UAB" },
    { 0x052A,   "Keynes Controls Ltd" },
    { 0x052B,   "Novartis AG" },
    { 0x052C,   "Geosatis SA" },
    { 0x052D,   "EXFO, Inc." },
    { 0x052E,   "LEDVANCE GmbH" },
    { 0x052F,   "Center ID Corp." },
    { 0x0530,   "Adolene, Inc." },
    { 0x0531,   "D&M Holdings Inc." },
    { 0x0532,   "CRESCO Wireless, Inc." },
    { 0x0533,   "Nura Operations Pty Ltd" },
    { 0x0534,   "Frontiergadget, Inc." },
    { 0x0535,   "Smart Component Technologies Limited" },
    { 0x0536,   "ZTR Control Systems LLC" },
    { 0x0537,   "MetaLogics Corporation" },
    { 0x0538,   "Medela AG" },
    { 0x0539,   "OPPLE Lighting Co., Ltd" },
    { 0x053A,   "Savitech Corp.," },
    { 0x053B,   "prodigy" },
    { 0x053C,   "Screenovate Technologies Ltd" },
    { 0x053D,   "TESA SA" },
    { 0x053E,   "CLIM8 LIMITED" },
    { 0x053F,   "Silergy Corp" },
    { 0x0540,   "SilverPlus, Inc" },
    { 0x0541,   "Sharknet srl" },
    { 0x0542,   "Mist Systems, Inc." },
    { 0x0543,   "MIWA LOCK CO.,Ltd" },
    { 0x0544,   "OrthoSensor, Inc." },
    { 0x0545,   "Candy Hoover Group s.r.l" },
    { 0x0546,   "Apexar Technologies S.A." },
    { 0x0547,   "LOGICDATA d.o.o." },
    { 0x0548,   "Knick Elektronische Messgeraete GmbH & Co. KG" },
    { 0x0549,   "Smart Technologies and Investment Limited" },
    { 0x054A,   "Linough Inc." },
    { 0x054B,   "Advanced Electronic Designs, Inc." },
    { 0x054C,   "Carefree Scott Fetzer Co Inc" },
    { 0x054D,   "Sensome" },
    { 0x054E,   "FORTRONIK storitve d.o.o." },
    { 0x054F,   "Sinnoz" },
    { 0x0550,   "Versa Networks, Inc." },
    { 0x0551,   "Sylero" },
    { 0x0552,   "Avempace SARL" },
    { 0x0553,   "Nintendo Co., Ltd." },
    { 0x0554,   "National Instruments" },
    { 0x0555,   "KROHNE Messtechnik GmbH" },
    { 0x0556,   "Otodynamics Ltd" },
    { 0x0557,   "Arwin Technology Limited" },
    { 0x0558,   "benegear, inc." },
    { 0x0559,   "Newcon Optik" },
    { 0x055A,   "CANDY HOUSE, Inc." },
    { 0x055B,   "FRANKLIN TECHNOLOGY INC" },
    { 0x055C,   "Lely" },
    { 0x055D,   "Valve Corporation" },
    { 0x055E,   "Hekatron Vertriebs GmbH" },
    { 0x055F,   "PROTECH S.A.S. DI GIRARDI ANDREA & C." },
    { 0x0560,   "Sarita CareTech APS (formerly Sarita CareTech IVS)" },
    { 0x0561,   "Finder S.p.A." },
    { 0x0562,   "Thalmic Labs Inc." },
    { 0x0563,   "Steinel Vertrieb GmbH" },
    { 0x0564,   "Beghelli Spa" },
    { 0x0565,   "Beijing Smartspace Technologies Inc." },
    { 0x0566,   "CORE TRANSPORT TECHNOLOGIES NZ LIMITED" },
    { 0x0567,   "Xiamen Everesports Goods Co., Ltd" },
    { 0x0568,   "Bodyport Inc." },
    { 0x0569,   "Audionics System, INC." },
    { 0x056A,   "Flipnavi Co.,Ltd." },
    { 0x056B,   "Rion Co., Ltd." },
    { 0x056C,   "Long Range Systems, LLC" },
    { 0x056D,   "Redmond Industrial Group LLC" },
    { 0x056E,   "VIZPIN INC." },
    { 0x056F,   "BikeFinder AS" },
    { 0x0570,   "Consumer Sleep Solutions LLC" },
    { 0x0571,   "PSIKICK, INC." },
    { 0x0572,   "AntTail.com" },
    { 0x0573,   "Lighting Science Group Corp." },
    { 0x0574,   "AFFORDABLE ELECTRONICS INC" },
    { 0x0575,   "Integral Memroy Plc" },
    { 0x0576,   "Globalstar, Inc." },
    { 0x0577,   "True Wearables, Inc." },
    { 0x0578,   "Wellington Drive Technologies Ltd" },
    { 0x0579,   "Ensemble Tech Private Limited" },
    { 0x057A,   "OMNI Remotes" },
    { 0x057B,   "Duracell U.S. Operations Inc." },
    { 0x057C,   "Toor Technologies LLC" },
    { 0x057D,   "Instinct Performance" },
    { 0x057E,   "Beco, Inc" },
    { 0x057F,   "Scuf Gaming International, LLC" },
    { 0x0580,   "ARANZ Medical Limited" },
    { 0x0581,   "LYS TECHNOLOGIES LTD" },
    { 0x0582,   "Breakwall Analytics, LLC" },
    { 0x0583,   "Code Blue Communications" },
    { 0x0584,   "Gira Giersiepen GmbH & Co. KG" },
    { 0x0585,   "Hearing Lab Technology" },
    { 0x0586,   "LEGRAND" },
    { 0x0587,   "Derichs GmbH" },
    { 0x0588,   "ALT-TEKNIK LLC" },
    { 0x0589,   "Star Technologies" },
    { 0x058A,   "START TODAY CO.,LTD." },
    { 0x058B,   "Maxim Integrated Products" },
    { 0x058C,   "MERCK Kommanditgesellschaft auf Aktien" },
    { 0x058D,   "Jungheinrich Aktiengesellschaft" },
    { 0x058E,   "Oculus VR, LLC" },
    { 0x058F,   "HENDON SEMICONDUCTORS PTY LTD" },
    { 0x0590,   "Pur3 Ltd" },
    { 0x0591,   "Viasat Group S.p.A." },
    { 0x0592,   "IZITHERM" },
    { 0x0593,   "Spaulding Clinical Research" },
    { 0x0594,   "Kohler Company" },
    { 0x0595,   "Inor Process AB" },
    { 0x0596,   "My Smart Blinds" },
    { 0x0597,   "RadioPulse Inc" },
    { 0x0598,   "rapitag GmbH" },
    { 0x0599,   "Lazlo326, LLC." },
    { 0x059A,   "Teledyne Lecroy, Inc." },
    { 0x059B,   "Dataflow Systems Limited" },
    { 0x059C,   "Macrogiga Electronics" },
    { 0x059D,   "Tandem Diabetes Care" },
    { 0x059E,   "Polycom, Inc." },
    { 0x059F,   "Fisher & Paykel Healthcare" },
    { 0x05A0,   "RCP Software Oy" },
    { 0x05A1,   "Shanghai Xiaoyi Technology Co.,Ltd." },
    { 0x05A2,   "ADHERIUM(NZ) LIMITED" },
    { 0x05A3,   "Axiomware Systems Incorporated" },
    { 0x05A4,   "O. E. M. Controls, Inc." },
    { 0x05A5,   "Kiiroo BV" },
    { 0x05A6,   "Telecon Mobile Limited" },
    { 0x05A7,   "Sonos Inc" },
    { 0x05A8,   "Tom Allebrandi Consulting" },
    { 0x05A9,   "Monidor" },
    { 0x05AA,   "Tramex Limited" },
    { 0x05AB,   "Nofence AS" },
    { 0x05AC,   "GoerTek Dynaudio Co., Ltd." },
    { 0x05AD,   "INIA" },
    { 0x05AE,   "CARMATE MFG.CO.,LTD" },
    { 0x05AF,   "ONvocal" },
    { 0x05B0,   "NewTec GmbH" },
    { 0x05B1,   "Medallion Instrumentation Systems" },
    { 0x05B2,   "CAREL INDUSTRIES S.P.A." },
    { 0x05B3,   "Parabit Systems, Inc." },
    { 0x05B4,   "White Horse Scientific ltd" },
    { 0x05B5,   "verisilicon" },
    { 0x05B6,   "Elecs Industry Co.,Ltd." },
    { 0x05B7,   "Beijing Pinecone Electronics Co.,Ltd." },
    { 0x05B8,   "Ambystoma Labs Inc." },
    { 0x05B9,   "Suzhou Pairlink Network Technology" },
    { 0x05BA,   "igloohome" },
    { 0x05BB,   "Oxford Metrics plc" },
    { 0x05BC,   "Leviton Mfg. Co., Inc." },
    { 0x05BD,   "ULC Robotics Inc." },
    { 0x05BE,   "RFID Global by Softwork SrL" },
    { 0x05BF,   "Real-World-Systems Corporation" },
    { 0x05C0,   "Nalu Medical, Inc." },
    { 0x05C1,   "P.I.Engineering" },
    { 0x05C2,   "Grote Industries" },
    { 0x05C3,   "Runtime, Inc." },
    { 0x05C4,   "Codecoup sp. z o.o. sp. k." },
    { 0x05C5,   "SELVE GmbH & Co. KG" },
    { 0x05C6,   "Smart Animal Training Systems, LLC" },
    { 0x05C7,   "Lippert Components, INC" },
    { 0x05C8,   "SOMFY SAS" },
    { 0x05C9,   "TBS Electronics B.V." },
    { 0x05CA,   "MHL Custom Inc" },
    { 0x05CB,   "LucentWear LLC" },
    { 0x05CC,   "WATTS ELECTRONICS" },
    { 0x05CD,   "RJ Brands LLC" },
    { 0x05CE,   "V-ZUG Ltd" },
    { 0x05CF,   "Biowatch SA" },
    { 0x05D0,   "Anova Applied Electronics" },
    { 0x05D1,   "Lindab AB" },
    { 0x05D2,   "frogblue TECHNOLOGY GmbH" },
    { 0x05D3,   "Acurable Limited" },
    { 0x05D4,   "LAMPLIGHT Co., Ltd." },
    { 0x05D5,   "TEGAM, Inc." },
    { 0x05D6,   "Zhuhai Jieli technology Co.,Ltd" },
    { 0x05D7,   "modum.io AG" },
    { 0x05D8,   "Farm Jenny LLC" },
    { 0x05D9,   "Toyo Electronics Corporation" },
    { 0x05DA,   "Applied Neural Research Corp" },
    { 0x05DB,   "Avid Identification Systems, Inc." },
    { 0x05DC,   "Petronics Inc." },
    { 0x05DD,   "essentim GmbH" },
    { 0x05DE,   "QT Medical INC." },
    { 0x05DF,   "VIRTUALCLINIC.DIRECT LIMITED" },
    { 0x05E0,   "Viper Design LLC" },
    { 0x05E1,   "Human, Incorporated" },
    { 0x05E2,   "stAPPtronics GmbH" },
    { 0x05E3,   "Elemental Machines, Inc." },
    { 0x05E4,   "Taiyo Yuden Co., Ltd" },
    { 0x05E5,   "INEO ENERGY& SYSTEMS" },
    { 0x05E6,   "Motion Instruments Inc." },
    { 0x05E7,   "PressurePro" },
    { 0x05E8,   "COWBOY" },
    { 0x05E9,   "iconmobile GmbH" },
    { 0x05EA,   "ACS-Control-System GmbH" },
    { 0x05EB,   "Bayerische Motoren Werke AG" },
    { 0x05EC,   "Gycom Svenska AB" },
    { 0x05ED,   "Fuji Xerox Co., Ltd" },
    { 0x05EE,   "Glide Inc." },
    { 0x05EF,   "SIKOM AS" },
    { 0x05F0,   "beken" },
    { 0x05F1,   "The Linux Foundation" },
    { 0x05F2,   "Try and E CO.,LTD." },
    { 0x05F3,   "SeeScan" },
    { 0x05F4,   "Clearity, LLC" },
    { 0x05F5,   "GS TAG" },
    { 0x05F6,   "DPTechnics" },
    { 0x05F7,   "TRACMO, INC." },
    { 0x05F8,   "Anki Inc." },
    { 0x05F9,   "Hagleitner Hygiene International GmbH" },
    { 0x05FA,   "Konami Sports Life Co., Ltd." },
    { 0x05FB,   "Arblet Inc." },
    { 0x05FC,   "Masbando GmbH" },
    { 0x05FD,   "Innoseis" },
    { 0x05FE,   "Niko" },
    { 0x05FF,   "Wellnomics Ltd" },
    { 0x0600,   "iRobot Corporation" },
    { 0x0601,   "Schrader Electronics" },
    { 0x0602,   "Geberit International AG" },
    { 0x0603,   "Fourth Evolution Inc" },
    { 0x0604,   "Cell2Jack LLC" },
    { 0x0605,   "FMW electronic Futterer u. Maier-Wolf OHG" },
    { 0x0606,   "John Deere" },
    { 0x0607,   "Rookery Technology Ltd" },
    { 0x0608,   "KeySafe-Cloud" },
    { 0x0609,   "BUCHI Labortechnik AG" },
    { 0x060A,   "IQAir AG" },
    { 0x060B,   "Triax Technologies Inc" },
    { 0x060C,   "Vuzix Corporation" },
    { 0x060D,   "TDK Corporation" },
    { 0x060E,   "Blueair AB" },
    { 0x060F,   "Signify Netherlands" },
    { 0x0610,   "ADH GUARDIAN USA LLC" },
    { 0x0611,   "Beurer GmbH" },
    { 0x0612,   "Playfinity AS" },
    { 0x0613,   "Hans Dinslage GmbH" },
    { 0x0614,   "OnAsset Intelligence, Inc." },
    { 0x0615,   "INTER ACTION Corporation" },
    { 0x0616,   "OS42 UG (haftungsbeschraenkt)" },
    { 0x0617,   "WIZCONNECTED COMPANY LIMITED" },
    { 0x0618,   "Audio-Technica Corporation" },
    { 0x0619,   "Six Guys Labs, s.r.o." },
    { 0x061A,   "R.W. Beckett Corporation" },
    { 0x061B,   "silex technology, inc." },
    { 0x061C,   "Univations Limited" },
    { 0x061D,   "SENS Innovation ApS" },
    { 0x061E,   "Diamond Kinetics, Inc." },
    { 0x061F,   "Phrame Inc." },
    { 0x0620,   "Forciot Oy" },
    { 0x0621,   "Noordung d.o.o." },
    { 0x0622,   "Beam Labs, LLC" },
    { 0x0623,   "Philadelphia Scientific (U.K.) Limited" },
    { 0x0624,   "Biovotion AG" },
    { 0x0625,   "Square Panda, Inc." },
    { 0x0626,   "Amplifico" },
    { 0x0627,   "WEG S.A." },
    { 0x0628,   "Ensto Oy" },
    { 0x0629,   "PHONEPE PVT LTD" },
    { 0x062A,   "Lunatico Astronomia SL" },
    { 0x062B,   "MinebeaMitsumi Inc." },
    { 0x062C,   "ASPion GmbH" },
    { 0x062D,   "Vossloh-Schwabe Deutschland GmbH" },
    { 0x062E,   "Procept" },
    { 0x062F,   "ONKYO Corporation" },
    { 0x0630,   "Asthrea D.O.O." },
    { 0x0631,   "Fortiori Design LLC" },
    { 0x0632,   "Hugo Muller GmbH & Co KG" },
    { 0x0633,   "Wangi Lai PLT" },
    { 0x0634,   "Fanstel Corp" },
    { 0x0635,   "Crookwood" },
    { 0x0636,   "ELECTRONICA INTEGRAL DE SONIDO S.A." },
    { 0x0637,   "GiP Innovation Tools GmbH" },
    { 0x0638,   "LX SOLUTIONS PTY LIMITED" },
    { 0x0639,   "Shenzhen Minew Technologies Co., Ltd." },
    { 0x063A,   "Prolojik Limited" },
    { 0x063B,   "Kromek Group Plc" },
    { 0x063C,   "Contec Medical Systems Co., Ltd." },
    { 0x063D,   "Xradio Technology Co.,Ltd." },
    { 0x063E,   "The Indoor Lab, LLC" },
    { 0x063F,   "LDL TECHNOLOGY" },
    { 0x0640,   "Parkifi" },
    { 0x0641,   "Revenue Collection Systems FRANCE SAS" },
    { 0x0642,   "Bluetrum Technology Co.,Ltd" },
    { 0x0643,   "makita corporation" },
    { 0x0644,   "Apogee Instruments" },
    { 0x0645,   "BM3" },
    { 0x0646,   "SGV Group Holding GmbH & Co. KG" },
    { 0x0647,   "MED-EL" },
    { 0x0648,   "Ultune Technologies" },
    { 0x0649,   "Ryeex Technology Co.,Ltd." },
    { 0x064A,   "Open Research Institute, Inc." },
    { 0x064B,   "Scale-Tec, Ltd" },
    { 0x064C,   "Zumtobel Group AG" },
    { 0x064D,   "iLOQ Oy" },
    { 0x064E,   "KRUXWorks Technologies Private Limited" },
    { 0x064F,   "Digital Matter Pty Ltd" },
    { 0x0650,   "Coravin, Inc." },
    { 0x0651,   "Stasis Labs, Inc." },
    { 0x0652,   "ITZ Innovations- und Technologiezentrum GmbH" },
    { 0x0653,   "Meggitt SA" },
    { 0x0654,   "Ledlenser GmbH & Co. KG" },
    { 0x0655,   "Renishaw PLC" },
    { 0x0656,   "ZhuHai AdvanPro Technology Company Limited" },
    { 0x0657,   "Meshtronix Limited" },
    { 0x0658,   "Payex Norge AS" },
    { 0x0659,   "UnSeen Technologies Oy" },
    { 0x065A,   "Zound Industries International AB" },
    { 0x065B,   "Sesam Solutions BV" },
    { 0x065C,   "PixArt Imaging Inc." },
    { 0x065D,   "Panduit Corp." },
    { 0x065E,   "Alo AB" },
    { 0x065F,   "Ricoh Company Ltd" },
    { 0x0660,   "RTC Industries, Inc." },
    { 0x0661,   "Mode Lighting Limited" },
    { 0x0662,   "Particle Industries, Inc." },
    { 0x0663,   "Advanced Telemetry Systems, Inc." },
    { 0x0664,   "RHA TECHNOLOGIES LTD" },
    { 0x0665,   "Pure International Limited" },
    { 0x0666,   "WTO Werkzeug-Einrichtungen GmbH" },
    { 0x0667,   "Spark Technology Labs Inc." },
    { 0x0668,   "Bleb Technology srl" },
    { 0x0669,   "Livanova USA, Inc." },
    { 0x066A,   "Brady Worldwide Inc." },
    { 0x066B,   "DewertOkin GmbH" },
    { 0x066C,   "Ztove ApS" },
    { 0x066D,   "Venso EcoSolutions AB" },
    { 0x066E,   "Eurotronik Kranj d.o.o." },
    { 0x066F,   "Hug Technology Ltd" },
    { 0x0670,   "Gema Switzerland GmbH" },
    { 0x0671,   "Buzz Products Ltd." },
    { 0x0672,   "Kopi" },
    { 0x0673,   "Innova Ideas Limited" },
    { 0x0674,   "BeSpoon" },
    { 0x0675,   "Deco Enterprises, Inc." },
    { 0x0676,   "Expai Solutions Private Limited" },
    { 0x0677,   "Innovation First, Inc." },
    { 0x0678,   "SABIK Offshore GmbH" },
    { 0x0679,   "4iiii Innovations Inc." },
    { 0x067A,   "The Energy Conservatory, Inc." },
    { 0x067B,   "I.FARM, INC." },
    { 0x067C,   "Tile, Inc." },
    { 0x067D,   "Form Athletica Inc." },
    { 0x067E,   "MbientLab Inc" },
    { 0x067F,   "NETGRID S.N.C. DI BISSOLI MATTEO, CAMPOREALE SIMONE, TOGNETTI FEDERICO" },
    { 0x0680,   "Mannkind Corporation" },
    { 0x0681,   "Trade FIDES a.s." },
    { 0x0682,   "Photron Limited" },
    { 0x0683,   "Eltako GmbH" },
    { 0x0684,   "Dermalapps, LLC" },
    { 0x0685,   "Greenwald Industries" },
    { 0x0686,   "inQs Co., Ltd." },
    { 0x0687,   "Cherry GmbH" },
    { 0x0688,   "Amsted Digital Solutions Inc." },
    { 0x0689,   "Tacx b.v." },
    { 0x068A,   "Raytac Corporation" },
    { 0x068B,   "Jiangsu Teranovo Tech Co., Ltd." },
    { 0x068C,   "Changzhou Sound Dragon Electronics and Acoustics Co., Ltd" },
    { 0x068D,   "JetBeep Inc." },
    { 0x068E,   "Razer Inc." },
    { 0x068F,   "JRM Group Limited" },
    { 0x0690,   "Eccrine Systems, Inc." },
    { 0x0691,   "Curie Point AB" },
    { 0x0692,   "Georg Fischer AG" },
    { 0x0693,   "Hach - Danaher" },
    { 0x0694,   "T&A Laboratories LLC" },
    { 0x0695,   "Koki Holdings Co., Ltd." },
    { 0x0696,   "Gunakar Private Limited" },
    { 0x0697,   "Stemco Products Inc" },
    { 0x0698,   "Wood IT Security, LLC" },
    { 0x0699,   "RandomLab SAS" },
    { 0x069A,   "Adero, Inc. (formerly as TrackR, Inc.)" },
    { 0x069B,   "Dragonchip Limited" },
    { 0x069C,   "Noomi AB" },
    { 0x069D,   "Vakaros LLC" },
    { 0x069E,   "Delta Electronics, Inc." },
    { 0x069F,   "FlowMotion Technologies AS" },
    { 0x06A0,   "OBIQ Location Technology Inc." },
    { 0x06A1,   "Cardo Systems, Ltd" },
    { 0x06A2,   "Globalworx GmbH" },
    { 0x06A3,   "Nymbus, LLC" },
    { 0x06A4,   "Sanyo Techno Solutions Tottori Co., Ltd." },
    { 0x06A5,   "TEKZITEL PTY LTD" },
    { 0x06A6,   "Roambee Corporation" },
    { 0x06A7,   "Chipsea Technologies (ShenZhen) Corp." },
    { 0x06A8,   "GD Midea Air-Conditioning Equipment Co., Ltd." },
    { 0x06A9,   "Soundmax Electronics Limited" },
    { 0x06AA,   "Produal Oy" },
    { 0x06AB,   "HMS Industrial Networks AB" },
    { 0x06AC,   "Ingchips Technology Co., Ltd." },
    { 0x06AD,   "InnovaSea Systems Inc." },
    { 0x06AE,   "SenseQ Inc." },
    { 0x06AF,   "Shoof Technologies" },
    { 0x06B0,   "BRK Brands, Inc." },
    { 0x06B1,   "SimpliSafe, Inc." },
    { 0x06B2,   "Tussock Innovation 2013 Limited" },
    { 0x06B3,   "The Hablab ApS" },
    { 0x06B4,   "Sencilion Oy" },
    { 0x06B5,   "Wabilogic Ltd." },
    { 0x06B6,   "Sociometric Solutions, Inc." },
    { 0x06B7,   "iCOGNIZE GmbH" },
    { 0x06B8,   "ShadeCraft, Inc" },
    { 0x06B9,   "Beflex Inc." },
    { 0x06BA,   "Beaconzone Ltd" },
    { 0x06BB,   "Leaftronix Analogic Solutions Private Limited" },
    { 0x06BC,   "TWS Srl" },
    { 0x06BD,   "ABB Oy" },
    { 0x06BE,   "HitSeed Oy" },
    { 0x06BF,   "Delcom Products Inc." },
    { 0x06C0,   "CAME S.p.A." },
    { 0x06C1,   "Alarm.com Holdings, Inc" },
    { 0x06C2,   "Measurlogic Inc." },
    { 0x06C3,   "King I Electronics.Co.,Ltd" },
    { 0x06C4,   "Dream Labs GmbH" },
    { 0x06C5,   "Urban Compass, Inc" },
    { 0x06C6,   "Simm Tronic Limited" },
    { 0x06C7,   "Somatix Inc" },
    { 0x06C8,   "Storz & Bickel GmbH & Co. KG" },
    { 0x06C9,   "MYLAPS B.V." },
    { 0x06CA,   "Shenzhen Zhongguang Infotech Technology Development Co., Ltd" },
    { 0x06CB,   "Dyeware, LLC" },
    { 0x06CC,   "Dongguan SmartAction Technology Co.,Ltd." },
    { 0x06CD,   "DIG Corporation" },
    { 0x06CE,   "FIOR & GENTZ" },
    { 0x06CF,   "Belparts N.V." },
    { 0x06D0,   "Etekcity Corporation" },
    { 0x06D1,   "Meyer Sound Laboratories, Incorporated" },
    { 0x06D2,   "CeoTronics AG" },
    { 0x06D3,   "TriTeq Lock and Security, LLC" },
    { 0x06D4,   "DYNAKODE TECHNOLOGY PRIVATE LIMITED" },
    { 0x06D5,   "Sensirion AG" },
    { 0x06D6,   "JCT Healthcare Pty Ltd" },
    { 0x06D7,   "FUBA Automotive Electronics GmbH" },
    { 0x06D8,   "AW Company" },
    { 0x06D9,   "Shanghai Mountain View Silicon Co.,Ltd." },
    { 0x06DA,   "Zliide Technologies ApS" },
    { 0x06DB,   "Automatic Labs, Inc." },
    { 0x06DC,   "Industrial Network Controls, LLC" },
    { 0x06DD,   "Intellithings Ltd." },
    { 0x06DE,   "Navcast, Inc." },
    { 0x06DF,   "Hubbell Lighting, Inc." },
    { 0x06E0,   "Avaya" },
    { 0x06E1,   "Milestone AV Technologies LLC" },
    { 0x06E2,   "Alango Technologies Ltd" },
    { 0x06E3,   "Spinlock Ltd" },
    { 0x06E4,   "Aluna" },
    { 0x06E5,   "OPTEX CO.,LTD." },
    { 0x06E6,   "NIHON DENGYO KOUSAKU" },
    { 0x06E7,   "VELUX A/S" },
    { 0x06E8,   "Almendo Technologies GmbH" },
    { 0x06E9,   "Zmartfun Electronics, Inc." },
    { 0x06EA,   "SafeLine Sweden AB" },
    { 0x06EB,   "Houston Radar LLC" },
    { 0x06EC,   "Sigur" },
    { 0x06ED,   "J Neades Ltd" },
    { 0x06EE,   "Avantis Systems Limited" },
    { 0x06EF,   "ALCARE Co., Ltd." },
    { 0x06F0,   "Chargy Technologies, SL" },
    { 0x06F1,   "Shibutani Co., Ltd." },
    { 0x06F2,   "Trapper Data AB" },
    { 0x06F3,   "Alfred International Inc." },
    { 0x06F4,   "Near Field Solutions Ltd" },
    { 0x06F5,   "Vigil Technologies Inc." },
    { 0x06F6,   "Vitulo Plus BV" },
    { 0x06F7,   "WILKA Schliesstechnik GmbH" },
    { 0x06F8,   "BodyPlus Technology Co.,Ltd" },
    { 0x06F9,   "happybrush GmbH" },
    { 0x06FA,   "Enequi AB" },
    { 0x06FB,   "Sartorius AG" },
    { 0x06FC,   "Tom Communication Industrial Co.,Ltd." },
    { 0x06FD,   "ESS Embedded System Solutions Inc." },
    { 0x06FE,   "Mahr GmbH" },
    { 0x06FF,   "Redpine Signals Inc" },
    { 0x0700,   "TraqFreq LLC" },
    { 0x0701,   "PAFERS TECH" },
    { 0x0702,   "Akciju sabiedriba \"SAF TEHNIKA\"" },
    { 0x0703,   "Beijing Jingdong Century Trading Co., Ltd." },
    { 0x0704,   "JBX Designs Inc." },
    { 0x0705,   "AB Electrolux" },
    { 0x0706,   "Wernher von Braun Center for ASdvanced Research" },
    { 0x0707,   "Essity Hygiene and Health Aktiebolag" },
    { 0x0708,   "Be Interactive Co., Ltd" },
    { 0x0709,   "Carewear Corp." },
    { 0x070A,   "Huf Hlsbeck & Frst GmbH & Co. KG" },
    { 0x070B,   "Element Products, Inc." },
    { 0x070C,   "Beijing Winner Microelectronics Co.,Ltd" },
    { 0x070D,   "SmartSnugg Pty Ltd" },
    { 0x070E,   "FiveCo Sarl" },
    { 0x070F,   "California Things Inc." },
    { 0x0710,   "Audiodo AB" },
    { 0x0711,   "ABAX AS" },
    { 0x0712,   "Bull Group Company Limited" },
    { 0x0713,   "Respiri Limited" },
    { 0x0714,   "MindPeace Safety LLC" },
    { 0x0715,   "Vgyan Solutions" },
    { 0x0716,   "Altonics" },
    { 0x0717,   "iQsquare BV" },
    { 0x0718,   "IDIBAIX enginneering" },
    { 0x0719,   "ECSG" },
    { 0x071A,   "REVSMART WEARABLE HK CO LTD" },
    { 0x071B,   "Precor" },
    { 0x071C,   "F5 Sports, Inc" },
    { 0x071D,   "exoTIC Systems" },
    { 0x071E,   "DONGGUAN HELE ELECTRONICS CO., LTD" },
    { 0x071F,   "Dongguan Liesheng Electronic Co.Ltd" },
    { 0x0720,   "Oculeve, Inc." },
    { 0x0721,   "Clover Network, Inc." },
    { 0x0722,   "Xiamen Eholder Electronics Co.Ltd" },
    { 0x0723,   "Ford Motor Company" },
    { 0x0724,   "Guangzhou SuperSound Information Technology Co.,Ltd" },
    { 0x0725,   "Tedee Sp. z o.o." },
    { 0x0726,   "PHC Corporation" },
    { 0x0727,   "STALKIT AS" },
    { 0x0728,   "Eli Lilly and Company" },
    { 0x0729,   "SwaraLink Technologies" },
    { 0x072A,   "JMR embedded systems GmbH" },
    { 0x072B,   "Bitkey Inc." },
    { 0x072C,   "GWA Hygiene GmbH" },
    { 0x072D,   "Safera Oy" },
    { 0x072E,   "Open Platform Systems LLC" },
    { 0x072F,   "OnePlus Electronics (Shenzhen) Co., Ltd." },
    { 0x0730,   "Wildlife Acoustics, Inc." },
    { 0x0731,   "ABLIC Inc." },
    { 0x0732,   "Dairy Tech, Inc." },
    { 0x0733,   "Iguanavation, Inc." },
    { 0x0734,   "DiUS Computing Pty Ltd" },
    { 0x0735,   "UpRight Technologies LTD" },
    { 0x0736,   "FrancisFund, LLC" },
    { 0x0737,   "LLC Navitek" },
    { 0x0738,   "Glass Security Pte Ltd" },
    { 0x0739,   "Jiangsu Qinheng Co., Ltd." },
    { 0x073A,   "Chandler Systems Inc." },
    { 0x073B,   "Fantini Cosmi s.p.a." },
    { 0x073C,   "Acubit ApS" },
    { 0x073D,   "Beijing Hao Heng Tian Tech Co., Ltd." },
    { 0x073E,   "Bluepack S.R.L." },
    { 0x073F,   "Beijing Unisoc Technologies Co., Ltd." },
    { 0x0740,   "HITIQ LIMITED" },
    { 0x0741,   "MAC SRL" },
    { 0x0742,   "DML LLC" },
    { 0x0743,   "Sanofi" },
    { 0x0744,   "SOCOMEC" },
    { 0x0745,   "WIZNOVA, Inc." },
    { 0x0746,   "Seitec Elektronik GmbH" },
    { 0x0747,   "OR Technologies Pty Ltd" },
    { 0x0748,   "GuangZhou KuGou Computer Technology Co.Ltd" },
    { 0x0749,   "DIAODIAO (Beijing) Technology Co., Ltd." },
    { 0x074A,   "Illusory Studios LLC" },
    { 0x074B,   "Sarvavid Software Solutions LLP" },
    { 0x074C,   "iopool s.a." },
    { 0x074D,   "Amtech Systems, LLC" },
    { 0x074E,   "EAGLE DETECTION SA" },
    { 0x074F,   "MEDIATECH S.R.L." },
    { 0x0750,   "Hamilton Professional Services of Canada Incorporated" },
    { 0x0751,   "Changsha JEMO IC Design Co.,Ltd" },
    { 0x0752,   "Elatec GmbH" },
    { 0x0753,   "JLG Industries, Inc." },
    { 0x0754,   "Michael Parkin" },
    { 0x0755,   "Brother Industries, Ltd" },
    { 0x0756,   "Lumens For Less, Inc" },
    { 0x0757,   "ELA Innovation" },
    { 0x0758,   "umanSense AB" },
    { 0x0759,   "Shanghai InGeek Cyber Security Co., Ltd." },
    { 0x075A,   "HARMAN CO.,LTD." },
    { 0x075B,   "Smart Sensor Devices AB" },
    { 0x075C,   "Antitronics Inc." },
    { 0x075D,   "RHOMBUS SYSTEMS, INC." },
    { 0x075E,   "Katerra Inc." },
    { 0x075F,   "Remote Solution Co., LTD." },
    { 0x0760,   "Vimar SpA" },
    { 0x0761,   "Mantis Tech LLC" },
    { 0x0762,   "TerOpta Ltd" },
    { 0x0763,   "PIKOLIN S.L." },
    { 0x0764,   "WWZN Information Technology Company Limited" },
    { 0x0765,   "Voxx International" },
    { 0x0766,   "ART AND PROGRAM, INC." },
    { 0x0767,   "NITTO DENKO ASIA TECHNICAL CENTRE PTE. LTD." },
    { 0x0768,   "Peloton Interactive Inc." },
    { 0x0769,   "Force Impact Technologies" },
    { 0x076A,   "Dmac Mobile Developments, LLC" },
    { 0x076B,   "Engineered Medical Technologies" },
    { 0x076C,   "Noodle Technology inc" },
    { 0x076D,   "Graesslin GmbH" },
    { 0x076E,   "WuQi technologies, Inc." },
    { 0x076F,   "Successful Endeavours Pty Ltd" },
    { 0x0770,   "InnoCon Medical ApS" },
    { 0x0771,   "Corvex Connected Safety" },
    { 0x0772,   "Thirdwayv Inc." },
    { 0x0773,   "Echoflex Solutions Inc." },
    { 0x0774,   "C-MAX Asia Limited" },
    { 0x0775,   "4eBusiness GmbH" },
    { 0x0776,   "Cyber Transport Control GmbH" },
    { 0x0777,   "Cue" },
    { 0x0778,   "KOAMTAC INC." },
    { 0x0779,   "Loopshore Oy" },
    { 0x077A,   "Niruha Systems Private Limited" },
    { 0x077B,   "AmaterZ, Inc." },
    { 0x077C,   "radius co., ltd." },
    { 0x077D,   "Sensority, s.r.o." },
    { 0x077E,   "Sparkage Inc." },
    { 0x077F,   "Glenview Software Corporation" },
    { 0x0780,   "Finch Technologies Ltd." },
    { 0x0781,   "Qingping Technology (Beijing) Co., Ltd." },
    { 0x0782,   "DeviceDrive AS" },
    { 0x0783,   "ESEMBER LIMITED LIABILITY COMPANY" },
    { 0x0784,   "audifon GmbH & Co. KG" },
    { 0x0785,   "O2 Micro, Inc." },
    { 0x0786,   "HLP Controls Pty Limited" },
    { 0x0787,   "Pangaea Solution" },
    { 0x0788,   "BubblyNet, LLC" },
    { 0x078A,   "The Wildflower Foundation" },
    { 0x078B,   "Optikam Tech Inc." },
    { 0x078C,   "MINIBREW HOLDING B.V" },
    { 0x078D,   "Cybex GmbH" },
    { 0x078E,   "FUJIMIC NIIGATA, INC." },
    { 0x078F,   "Hanna Instruments, Inc." },
    { 0x0790,   "KOMPAN A/S" },
    { 0x0791,   "Scosche Industries, Inc." },
    { 0x0792,   "Provo Craft" },
    { 0x0793,   "AEV spol. s r.o." },
    { 0x0794,   "The Coca-Cola Company" },
    { 0x0795,   "GASTEC CORPORATION" },
    { 0x0796,   "StarLeaf Ltd" },
    { 0x0797,   "Water-i.d. GmbH" },
    { 0x0798,   "HoloKit, Inc." },
    { 0x0799,   "PlantChoir Inc." },
    { 0x079A,   "GuangDong Oppo Mobile Telecommunications Corp., Ltd." },
    { 0x079B,   "CST ELECTRONICS (PROPRIETARY) LIMITED" },
    { 0x079C,   "Sky UK Limited" },
    { 0x079D,   "Digibale Pty Ltd" },
    { 0x079E,   "Smartloxx GmbH" },
    { 0x079F,   "Pune Scientific LLP" },
    { 0x07A0,   "Regent Beleuchtungskorper AG" },
    { 0x07A1,   "Apollo Neuroscience, Inc." },
    { 0x07A2,   "Roku, Inc." },
    { 0x07A3,   "Comcast Cable" },
    { 0x07A4,   "Xiamen Mage Information Technology Co., Ltd." },
    { 0x07A5,   "RAB Lighting, Inc." },
    { 0x07A6,   "Musen Connect, Inc." },
    { 0x07A7,   "Zume, Inc." },
    { 0x07A8,   "conbee GmbH" },
    { 0x07A9,   "Bruel & Kjaer Sound & Vibration" },
    { 0x07AA,   "The Kroger Co." },
    { 0x07AB,   "Granite River Solutions, Inc." },
    { 0x07AC,   "LoupeDeck Oy" },
    { 0x07AD,   "New H3C Technologies Co.,Ltd" },
    { 0x07AE,   "Aurea Solucoes Tecnologicas Ltda." },
    { 0x07AF,   "Hong Kong Bouffalo Lab Limited" },
    { 0x07B0,   "GV Concepts Inc." },
    { 0x07B1,   "Thomas Dynamics, LLC" },
    { 0x07B2,   "Moeco IOT Inc." },
    { 0x07B3,   "2N TELEKOMUNIKACE a.s." },
    { 0x07B4,   "Hormann KG Antriebstechnik" },
    { 0x07B5,   "CRONO CHIP, S.L." },
    { 0x07B6,   "Soundbrenner Limited" },
    { 0x07B7,   "ETABLISSEMENTS GEORGES RENAULT" },
    { 0x07B8,   "iSwip" },
    { 0x07B9,   "Epona Biotec Limited" },
    { 0x07BA,   "Battery-Biz Inc." },
    { 0x07BB,   "EPIC S.R.L." },
    { 0x07BC,   "KD CIRCUITS LLC" },
    { 0x07BD,   "Genedrive Diagnostics Ltd" },
    { 0x07BE,   "Axentia Technologies AB" },
    { 0x07BF,   "REGULA Ltd." },
    { 0x07C0,   "Biral AG" },
    { 0x07C1,   "A.W. Chesterton Company" },
    { 0x07C2,   "Radinn AB" },
    { 0x07C3,   "CIMTechniques, Inc." },
    { 0x07C4,   "Johnson Health Tech NA" },
    { 0x07C5,   "June Life, Inc." },
    { 0x07C6,   "Bluenetics GmbH" },
    { 0x07C7,   "iaconicDesign Inc." },
    { 0x07C8,   "WRLDS Creations AB" },
    { 0x07C9,   "Skullcandy, Inc." },
    { 0x07CA,   "Modul-System HH AB" },
    { 0x07CB,   "West Pharmaceutical Services, Inc." },
    { 0x07CC,   "Barnacle Systems Inc." },
    { 0x07CD,   "Smart Wave Technologies Canada Inc" },
    { 0x07CE,   "Shanghai Top-Chip Microelectronics Tech. Co., LTD" },
    { 0x07CF,   "NeoSensory, Inc." },
    { 0x07D0,   "Hangzhou Tuya Information Technology Co., Ltd" },
    { 0x07D1,   "Shanghai Panchip Microelectronics Co., Ltd" },
    { 0x07D2,   "React Accessibility Limited" },
    { 0x07D3,   "LIVNEX Co.,Ltd." },
    { 0x07D4,   "Kano Computing Limited" },
    { 0x07D5,   "hoots classic GmbH" },
    { 0x07D6,   "ecobee Inc." },
    { 0x07D7,   "Nanjing Qinheng Microelectronics Co., Ltd" },
    { 0x07D8,   "SOLUTIONS AMBRA INC." },
    { 0x07D9,   "Micro-Design, Inc." },
    { 0x07DA,   "STARLITE Co., Ltd." },
    { 0x07DB,   "Remedee Labs" },
    { 0x07DC,   "ThingOS GmbH" },
    { 0x07DD,   "Linear Circuits" },
    { 0x07DE,   "Unlimited Engineering SL" },
    { 0x07DF,   "Snap-on Incorporated" },
    { 0x07E0,   "Edifier International Limited" },
    { 0x07E1,   "Lucie Labs" },
    { 0x07E2,   "Alfred Kaercher SE & Co. KG" },
    { 0x07E3,   "Audiowise Technology Inc." },
    { 0x07E4,   "Geeksme S.L." },
    { 0x07E5,   "Minut, Inc." },
    { 0x07E6,   "Autogrow Systems Limited" },
    { 0x07E7,   "Komfort IQ, Inc." },
    { 0x07E8,   "Packetcraft, Inc." },
    { 0x07E9,   "Häfele GmbH & Co KG" },
    { 0x07EA,   "ShapeLog, Inc." },
    { 0x07EB,   "NOVABASE S.R.L." },
    { 0x07EC,   "Frecce LLC" },
    { 0x07ED,   "Joule IQ, INC." },
    { 0x07EE,   "KidzTek LLC" },
    { 0x07EF,   "Aktiebolaget Sandvik Coromant" },
    { 0x07F0,   "e-moola.com Pty Ltd" },
    { 0x07F1,   "GSM Innovations Pty Ltd" },
    { 0x07F2,   "SERENE GROUP, INC" },
    { 0x07F3,   "DIGISINE ENERGYTECH CO. LTD." },
    { 0x07F4,   "MEDIRLAB Orvosbiologiai Fejleszto Korlatolt Felelossegu Tarsasag" },
    { 0x07F5,   "Byton North America Corporation" },
    { 0x07F6,   "Shenzhen TonliScience and Technology Development Co.,Ltd" },
    { 0x07F7,   "Cesar Systems Ltd." },
    { 0x07F8,   "quip NYC Inc." },
    { 0x07F9,   "Direct Communication Solutions, Inc." },
    { 0x07FA,   "Klipsch Group, Inc." },
    { 0x07FB,   "Access Co., Ltd" },
    { 0x07FC,   "Renault SA" },
    { 0x07FD,   "JSK CO., LTD." },
    { 0x07FE,   "BIROTA" },
    { 0x07FF,   "maxon motor ltd." },
    { 0x0800,   "Optek" },
    { 0x0801,   "CRONUS ELECTRONICS LTD" },
    { 0x0802,   "NantSound, Inc." },
    { 0x0803,   "Domintell s.a." },
    { 0x0804,   "Andon Health Co.,Ltd" },
    { 0x0805,   "Urbanminded Ltd" },
    { 0x0806,   "TYRI Sweden AB" },
    { 0x0807,   "ECD Electronic Components GmbH Dresden" },
    { 0x0808,   "SISTEMAS KERN, SOCIEDAD ANÓMINA" },
    { 0x0809,   "Trulli Audio" },
    { 0x080A,   "Altaneos" },
    { 0x080B,   "Nanoleaf Canada Limited" },
    { 0x080C,   "Ingy B.V." },
    { 0x080D,   "Azbil Co." },
    { 0x080E,   "TATTCOM LLC" },
    { 0x080F,   "Paradox Engineering SA" },
    { 0x0810,   "LECO Corporation" },
    { 0x0811,   "Becker Antriebe GmbH" },
    { 0x0812,   "Mstream Technologies., Inc." },
    { 0x0813,   "Flextronics International USA Inc." },
    { 0x0814,   "Ossur hf." },
    { 0x0815,   "SKC Inc" },
    { 0x0816,   "SPICA SYSTEMS LLC" },
    { 0x0817,   "Wangs Alliance Corporation" },
    { 0x0818,   "tatwah SA" },
    { 0x0819,   "Hunter Douglas Inc" },
    { 0x081A,   "Shenzhen Conex" },
    { 0x081B,   "DIM3" },
    { 0x081C,   "Bobrick Washroom Equipment, Inc." },
    { 0x081D,   "Potrykus Holdings and Development LLC" },
    { 0x081E,   "iNFORM Technology GmbH" },
    { 0x081F,   "eSenseLab LTD" },
    { 0x0820,   "Brilliant Home Technology, Inc." },
    { 0x0821,   "INOVA Geophysical, Inc." },
    { 0x0822,   "adafruit industries" },
    { 0x0823,   "Nexite Ltd" },
    { 0x0824,   "8Power Limited" },
    { 0x0825,   "CME PTE. LTD." },
    { 0x0826,   "Hyundai Motor Company" },
    { 0x0827,   "Kickmaker" },
    { 0x0828,   "Shanghai Suisheng Information Technology Co., Ltd." },
    { 0x0829,   "HEXAGON" },
    { 0x082A,   "Mitutoyo Corporation" },
    { 0x082B,   "shenzhen fitcare electronics Co.,Ltd" },
    { 0x082C,   "INGICS TECHNOLOGY CO., LTD." },
    { 0x082D,   "INCUS PERFORMANCE LTD." },
    { 0x082E,   "ABB S.p.A." },
    { 0x082F,   "Blippit AB" },
    { 0x0830,   "Core Health and Fitness LLC" },
    { 0x0831,   "Foxble, LLC" },
    { 0x0832,   "Intermotive,Inc." },
    { 0x0833,   "Conneqtech B.V." },
    { 0x0834,   "RIKEN KEIKI CO., LTD.," },
    { 0x0835,   "Canopy Growth Corporation" },
    { 0x0836,   "Bitwards Oy" },
    { 0x0837,   "vivo Mobile Communication Co., Ltd." },
    { 0x0838,   "Etymotic Research, Inc." },
    { 0x0839,   "A puissance 3" },
    { 0x083A,   "BPW Bergische Achsen Kommanditgesellschaft" },
    { 0x083B,   "Piaggio Fast Forward" },
    { 0x083C,   "BeerTech LTD" },
    { 0x083D,   "Tokenize, Inc." },
    { 0x083E,   "Zorachka LTD" },
    { 0x083F,   "D-Link Corp." },
    { 0x0840,   "Down Range Systems LLC" },
    { 0x0841,   "General Luminaire (Shanghai) Co., Ltd." },
    { 0x0842,   "Tangshan HongJia electronic technology co., LTD." },
    { 0x0843,   "FRAGRANCE DELIVERY TECHNOLOGIES LTD" },
    { 0x0844,   "Pepperl + Fuchs GmbH" },
    { 0x0845,   "Dometic Corporation" },
    { 0x0846,   "USound GmbH" },
    { 0x0847,   "DNANUDGE LIMITED" },
    { 0x0848,   "JUJU JOINTS CANADA CORP." },
    { 0x0849,   "Dopple Technologies B.V." },
    { 0x084A,   "ARCOM" },
    { 0x084B,   "Biotechware SRL" },
    { 0x084C,   "ORSO Inc." },
    { 0x084D,   "SafePort" },
    { 0x084E,   "Carol Cole Company" },
    { 0x084F,   "Embedded Fitness B.V." },
    { 0x0850,   "Yealink (Xiamen) Network Technology Co.,LTD" },
    { 0x0851,   "Subeca, Inc." },
    { 0x0852,   "Cognosos, Inc." },
    { 0x0853,   "Pektron Group Limited" },
    { 0x0854,   "Tap Sound System" },
    { 0x0855,   "Helios Hockey, Inc." },
    { 0x0856,   "Canopy Growth Corporation" },
    { 0x0857,   "Parsyl Inc" },
    { 0x0858,   "SOUNDBOKS" },
    { 0x0859,   "BlueUp" },
    { 0x085A,   "DAKATECH" },
    { 0x085B,   "RICOH ELECTRONIC DEVICES CO., LTD." },
    { 0x085C,   "ACOS CO.,LTD." },
    { 0x085D,   "Guilin Zhishen Information Technology Co.,Ltd." },
    { 0x085E,   "Krog Systems LLC" },
    { 0x085F,   "COMPEGPS TEAM,SOCIEDAD LIMITADA" },
    { 0x0860,   "Alflex Products B.V." },
    { 0x0861,   "SmartSensor Labs Ltd" },
    { 0x0862,   "SmartDrive Inc." },
    { 0x0863,   "Yo-tronics Technology Co., Ltd." },
    { 0x0864,   "Rafaelmicro" },
    { 0x0865,   "Emergency Lighting Products Limited" },
    { 0x0866,   "LAONZ Co.,Ltd" },
    { 0x0867,   "Western Digital Technologies, Inc." },
    { 0x0868,   "WIOsense GmbH & Co. KG" },
    { 0x0869,   "EVVA Sicherheitstechnologie GmbH" },
    { 0x086A,   "Odic Incorporated" },
    { 0x086B,   "Pacific Track, LLC" },
    { 0x086C,   "Revvo Technologies, Inc." },
    { 0x086D,   "Biometrika d.o.o." },
    { 0x086E,   "Vorwerk Elektrowerke GmbH & Co. KG" },
    { 0x086F,   "Trackunit A/S" },
    { 0x0870,   "Wyze Labs, Inc" },
    { 0x0871,   "Dension Elektronikai Kft. (formerly: Dension Audio Systems Ltd.)" },
    { 0x0872,   "11 Health & Technologies Limited" },
    { 0x0873,   "Innophase Incorporated" },
    { 0x0874,   "Treegreen Limited" },
    { 0x0875,   "Berner International LLC" },
    { 0x0876,   "SmartResQ ApS" },
    { 0x0877,   "Tome, Inc." },
    { 0x0878,   "The Chamberlain Group, Inc." },
    { 0x0879,   "MIZUNO Corporation" },
    { 0x087A,   "ZRF, LLC" },
    { 0x087B,   "BYSTAMP" },
    { 0x087C,   "Crosscan GmbH" },
    { 0x087D,   "Konftel AB" },
    { 0x087E,   "1bar.net Limited" },
    { 0x087F,   "Phillips Connect Technologies LLC" },
    { 0x0880,   "imagiLabs AB" },
    { 0x0881,   "Optalert" },
    { 0x0882,   "PSYONIC, Inc." },
    { 0x0883,   "Wintersteiger AG" },
    { 0x0884,   "Controlid Industria, Comercio de Hardware e Servicos de Tecnologia Ltda" },
    { 0x0885,   "LEVOLOR, INC." },
    { 0x0886,   "Xsens Technologies B.V." },
    { 0x0887,   "Hydro-Gear Limited Partnership" },
    { 0x0888,   "EnPointe Fencing Pty Ltd" },
    { 0x0889,   "XANTHIO" },
    { 0x088A,   "sclak s.r.l." },
    { 0x088B,   "Tricorder Arraay Technologies LLC" },
    { 0x088C,   "GB Solution co.,Ltd" },
    { 0x088D,   "Soliton Systems K.K." },
    { 0x088E,   "GIGA-TMS INC" },
    { 0x088F,   "Tait International Limited" },
    { 0x0890,   "NICHIEI INTEC CO., LTD." },
    { 0x0891,   "SmartWireless GmbH & Co. KG" },
    { 0x0892,   "Ingenieurbuero Birnfeld UG (haftungsbeschraenkt)" },
    { 0x0893,   "Maytronics Ltd" },
    { 0x0894,   "EPIFIT" },
    { 0x0895,   "Gimer medical" },
    { 0x0896,   "Nokian Renkaat Oyj" },
    { 0x0897,   "Current Lighting Solutions LLC" },
    { 0x0898,   "Sensibo, Inc." },
    { 0x0899,   "SFS unimarket AG" },
    { 0x089A,   "Private limited company \"Teltonika\"" },
    { 0x089B,   "Saucon Technologies" },
    { 0x089C,   "Embedded Devices Co. Company" },
    { 0x089D,   "J-J.A.D.E. Enterprise LLC" },
    { 0x089E,   "i-SENS, inc." },
    { 0x089F,   "Witschi Electronic Ltd" },
    { 0x08A0,   "Aclara Technologies LLC" },
    { 0x08A1,   "EXEO TECH CORPORATION" },
    { 0x08A2,   "Epic Systems Co., Ltd." },
    { 0x08A3,   "Hoffmann SE" },
    { 0x08A4,   "Realme Chongqing Mobile Telecommunications Corp., Ltd." },
    { 0x08A5,   "UMEHEAL Ltd" },
    { 0x08A6,   "Intelligenceworks Inc." },
    { 0x08A7,   "TGR 1.618 Limited" },
    { 0x08A8,   "Shanghai Kfcube Inc" },
    { 0x08A9,   "Fraunhofer IIS" },
    { 0x08AA,   "SZ DJI TECHNOLOGY CO.,LTD" },
    { 0xFFFF,   "For use in internal and interoperability tests" },
    {0, NULL }
};
value_string_ext bluetooth_company_id_vals_ext = VALUE_STRING_EXT_INIT(bluetooth_company_id_vals);

const value_string bluetooth_address_type_vals[] = {
    { 0x00,  "Public" },
    { 0x01,  "Random" },
    { 0, NULL }
};

/*
 * BLUETOOTH SPECIFICATION Version 4.0 [Vol 5] defines that
 * before transmission, the PAL shall remove the HCI header,
 * add LLC and SNAP headers and insert an 802.11 MAC header.
 * Protocol identifier are described in Table 5.2.
 */

#define AMP_U_L2CAP             0x0001
#define AMP_C_ACTIVITY_REPORT   0x0002
#define AMP_C_SECURITY_FRAME    0x0003
#define AMP_C_LINK_SUP_REQUEST  0x0004
#define AMP_C_LINK_SUP_REPLY    0x0005

static const value_string bluetooth_pid_vals[] = {
    { AMP_U_L2CAP,            "AMP_U L2CAP ACL data" },
    { AMP_C_ACTIVITY_REPORT,  "AMP-C Activity Report" },
    { AMP_C_SECURITY_FRAME,   "AMP-C Security frames" },
    { AMP_C_LINK_SUP_REQUEST, "AMP-C Link supervision request" },
    { AMP_C_LINK_SUP_REPLY,   "AMP-C Link supervision reply" },
    { 0,    NULL }
};

guint32 max_disconnect_in_frame = G_MAXUINT32;


void proto_register_bluetooth(void);
void proto_reg_handoff_bluetooth(void);

static void bluetooth_uuid_prompt(packet_info *pinfo, gchar* result)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID);
    if (value_data)
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "BT Service UUID %s as", (gchar *) value_data);
    else
        snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown BT Service UUID");
}

static gpointer bluetooth_uuid_value(packet_info *pinfo)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID);

    if (value_data)
        return (gpointer) value_data;

    return NULL;
}

gint
dissect_bd_addr(gint hf_bd_addr, packet_info *pinfo, proto_tree *tree,
        tvbuff_t *tvb, gint offset, gboolean is_local_bd_addr,
        guint32 interface_id, guint32 adapter_id, guint8 *bdaddr)
{
    guint8 bd_addr[6];

    bd_addr[5] = tvb_get_guint8(tvb, offset);
    bd_addr[4] = tvb_get_guint8(tvb, offset + 1);
    bd_addr[3] = tvb_get_guint8(tvb, offset + 2);
    bd_addr[2] = tvb_get_guint8(tvb, offset + 3);
    bd_addr[1] = tvb_get_guint8(tvb, offset + 4);
    bd_addr[0] = tvb_get_guint8(tvb, offset + 5);

    proto_tree_add_ether(tree, hf_bd_addr, tvb, offset, 6, bd_addr);
    offset += 6;

    if (have_tap_listener(bluetooth_device_tap)) {
        bluetooth_device_tap_t  *tap_device;

        tap_device = wmem_new(wmem_packet_scope(), bluetooth_device_tap_t);
        tap_device->interface_id = interface_id;
        tap_device->adapter_id   = adapter_id;
        memcpy(tap_device->bd_addr, bd_addr, 6);
        tap_device->has_bd_addr = TRUE;
        tap_device->is_local = is_local_bd_addr;
        tap_device->type = BLUETOOTH_DEVICE_BD_ADDR;
        tap_queue_packet(bluetooth_device_tap, pinfo, tap_device);
    }

    if (bdaddr)
        memcpy(bdaddr, bd_addr, 6);

    return offset;
}


void
save_local_device_name_from_eir_ad(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        guint8 size, bluetooth_data_t *bluetooth_data)
{
    gint                    i = 0;
    guint8                  length;
    wmem_tree_key_t         key[4];
    guint32                 k_interface_id;
    guint32                 k_adapter_id;
    guint32                 k_frame_number;
    gchar                   *name;
    localhost_name_entry_t  *localhost_name_entry;

    if (!(!pinfo->fd->visited && bluetooth_data)) return;

    while (i < size) {
        length = tvb_get_guint8(tvb, offset + i);
        if (length == 0) break;

        switch(tvb_get_guint8(tvb, offset + i + 1)) {
        case 0x08: /* Device Name, shortened */
        case 0x09: /* Device Name, full */
            name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + i + 2, length - 1, ENC_ASCII);

            k_interface_id = bluetooth_data->interface_id;
            k_adapter_id = bluetooth_data->adapter_id;
            k_frame_number = pinfo->num;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_frame_number;
            key[3].length = 0;
            key[3].key    = NULL;

            localhost_name_entry = (localhost_name_entry_t *) wmem_new(wmem_file_scope(), localhost_name_entry_t);
            localhost_name_entry->interface_id = k_interface_id;
            localhost_name_entry->adapter_id = k_adapter_id;
            localhost_name_entry->name = wmem_strdup(wmem_file_scope(), name);

            wmem_tree_insert32_array(bluetooth_data->localhost_name, key, localhost_name_entry);

            break;
        }

        i += length + 1;
    }
}


static const char* bluetooth_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == AT_ETHER)
            return "bluetooth.src";
        else if (conv->src_address.type == AT_STRINGZ)
            return "bluetooth.src_str";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == AT_ETHER)
            return "bluetooth.dst";
        else if (conv->dst_address.type == AT_STRINGZ)
            return "bluetooth.dst_str";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == AT_ETHER && conv->dst_address.type == AT_ETHER)
            return "bluetooth.addr";
        else if (conv->src_address.type == AT_STRINGZ && conv->dst_address.type == AT_STRINGZ)
            return "bluetooth.addr_str";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t bluetooth_ct_dissector_info = {&bluetooth_conv_get_filter_type};


static const char* bluetooth_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if (filter == CONV_FT_ANY_ADDRESS) {
        if (host->myaddress.type == AT_ETHER)
            return "bluetooth.addr";
        else if (host->myaddress.type == AT_STRINGZ)
            return "bluetooth.addr_str";
    }

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t  bluetooth_dissector_info = {&bluetooth_get_filter_type};


static tap_packet_status
bluetooth_conversation_packet(void *pct, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    add_conversation_table_data(hash, &pinfo->dl_src, &pinfo->dl_dst, 0, 0, 1,
            pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
            &bluetooth_ct_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}


static tap_packet_status
bluetooth_hostlist_packet(void *pit, packet_info *pinfo,
        epan_dissect_t *edt _U_, const void *vip _U_)
{
    conv_hash_t *hash = (conv_hash_t*) pit;

    add_hostlist_table_data(hash, &pinfo->dl_src, 0, TRUE,  1, pinfo->fd->pkt_len, &bluetooth_dissector_info, ENDPOINT_NONE);
    add_hostlist_table_data(hash, &pinfo->dl_dst, 0, FALSE, 1, pinfo->fd->pkt_len, &bluetooth_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static conversation_t *
get_conversation(packet_info *pinfo,
                     address *src_addr, address *dst_addr,
                     guint32 src_endpoint, guint32 dst_endpoint)
{
    conversation_t *conversation;

    conversation = find_conversation(pinfo->num,
                               src_addr, dst_addr,
                               ENDPOINT_BLUETOOTH,
                               src_endpoint, dst_endpoint, 0);
    if (conversation) {
        return conversation;
    }

    conversation = conversation_new(pinfo->num,
                           src_addr, dst_addr,
                           ENDPOINT_BLUETOOTH,
                           src_endpoint, dst_endpoint, 0);
    return conversation;
}

bluetooth_uuid_t
get_uuid(tvbuff_t *tvb, gint offset, gint size)
{
    bluetooth_uuid_t  uuid;

    memset(&uuid, 0, sizeof(uuid));

    if (size != 2 && size != 4 && size != 16) {
        return uuid;
    }

    uuid.size = size;
    if (size == 2) {
        uuid.data[0] = tvb_get_guint8(tvb, offset + 1);
        uuid.data[1] = tvb_get_guint8(tvb, offset);

        uuid.bt_uuid = uuid.data[1] | uuid.data[0] << 8;
    } else if (size == 4) {
        uuid.data[0] = tvb_get_guint8(tvb, offset + 3);
        uuid.data[1] = tvb_get_guint8(tvb, offset + 2);
        uuid.data[2] = tvb_get_guint8(tvb, offset + 1);
        uuid.data[3] = tvb_get_guint8(tvb, offset);

        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00)
            uuid.bt_uuid = uuid.data[2] | uuid.data[3] << 8;
    } else {
        uuid.data[0] = tvb_get_guint8(tvb, offset + 15);
        uuid.data[1] = tvb_get_guint8(tvb, offset + 14);
        uuid.data[2] = tvb_get_guint8(tvb, offset + 13);
        uuid.data[3] = tvb_get_guint8(tvb, offset + 12);
        uuid.data[4] = tvb_get_guint8(tvb, offset + 11);
        uuid.data[5] = tvb_get_guint8(tvb, offset + 10);
        uuid.data[6] = tvb_get_guint8(tvb, offset + 9);
        uuid.data[7] = tvb_get_guint8(tvb, offset + 8);
        uuid.data[8] = tvb_get_guint8(tvb, offset + 7);
        uuid.data[9] = tvb_get_guint8(tvb, offset + 6);
        uuid.data[10] = tvb_get_guint8(tvb, offset + 5);
        uuid.data[11] = tvb_get_guint8(tvb, offset + 4);
        uuid.data[12] = tvb_get_guint8(tvb, offset + 3);
        uuid.data[13] = tvb_get_guint8(tvb, offset + 2);
        uuid.data[14] = tvb_get_guint8(tvb, offset + 1);
        uuid.data[15] = tvb_get_guint8(tvb, offset);

        if (uuid.data[0] == 0x00 && uuid.data[1] == 0x00 &&
            uuid.data[4]  == 0x00 && uuid.data[5]  == 0x00 && uuid.data[6]  == 0x10 &&
            uuid.data[7]  == 0x00 && uuid.data[8]  == 0x80 && uuid.data[9]  == 0x00 &&
            uuid.data[10] == 0x00 && uuid.data[11] == 0x80 && uuid.data[12] == 0x5F &&
            uuid.data[13] == 0x9B && uuid.data[14] == 0x34 && uuid.data[15] == 0xFB)
            uuid.bt_uuid = uuid.data[2] | uuid.data[3] << 8;
    }

    return uuid;
}

const gchar *
print_numeric_uuid(bluetooth_uuid_t *uuid)
{
    if (!(uuid && uuid->size > 0))
        return NULL;

    if (uuid->size != 16) {
        return bytes_to_str(wmem_packet_scope(), uuid->data, uuid->size);
    } else {
        gchar *text;

        text = (gchar *) wmem_alloc(wmem_packet_scope(), 38);
        bytes_to_hexstr(&text[0], uuid->data, 4);
        text[8] = '-';
        bytes_to_hexstr(&text[9], uuid->data + 4, 2);
        text[13] = '-';
        bytes_to_hexstr(&text[14], uuid->data + 4 + 2 * 1, 2);
        text[18] = '-';
        bytes_to_hexstr(&text[19], uuid->data + 4 + 2 * 2, 2);
        text[23] = '-';
        bytes_to_hexstr(&text[24], uuid->data + 4 + 2 * 3, 6);
        text[36] = '\0';

        return text;
    }

    return NULL;
}

const gchar *
print_uuid(bluetooth_uuid_t *uuid)
{
    const gchar *description;

    if (uuid->bt_uuid) {
        const gchar *name;

        /*
         * Known UUID?
         */
        name = try_val_to_str_ext(uuid->bt_uuid, &bluetooth_uuid_vals_ext);
        if (name != NULL) {
            /*
             * Yes.  This string is part of the value_string_ext table,
             * so we don't have to make a copy.
             */
            return name;
        }

        /*
         * No - fall through to try looking it up.
         */
    }

    description = print_numeric_uuid(uuid);

    if (description) {
        description = (const gchar *) wmem_tree_lookup_string(bluetooth_uuids, description, 0);
        if (description)
            return description;
    }

    return "Unknown";
}

static bluetooth_data_t *
dissect_bluetooth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item        *main_item;
    proto_tree        *main_tree;
    proto_item        *sub_item;
    bluetooth_data_t  *bluetooth_data;
    address           *src;
    address           *dst;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bluetooth");
    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    default:
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
        break;
    }

    pinfo->ptype = PT_BLUETOOTH;
    get_conversation(pinfo, &pinfo->dl_src, &pinfo->dl_dst, pinfo->srcport, pinfo->destport);

    main_item = proto_tree_add_item(tree, proto_bluetooth, tvb, 0, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bluetooth);

    bluetooth_data = (bluetooth_data_t *) wmem_new(wmem_packet_scope(), bluetooth_data_t);
    if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        bluetooth_data->interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    else
        bluetooth_data->interface_id = HCI_INTERFACE_DEFAULT;
    bluetooth_data->adapter_id = HCI_ADAPTER_DEFAULT;
    bluetooth_data->adapter_disconnect_in_frame  = &max_disconnect_in_frame;
    bluetooth_data->chandle_sessions             = chandle_sessions;
    bluetooth_data->chandle_to_bdaddr            = chandle_to_bdaddr;
    bluetooth_data->chandle_to_mode              = chandle_to_mode;
    bluetooth_data->shandle_to_chandle           = shandle_to_chandle;
    bluetooth_data->bdaddr_to_name               = bdaddr_to_name;
    bluetooth_data->bdaddr_to_role               = bdaddr_to_role;
    bluetooth_data->localhost_bdaddr             = localhost_bdaddr;
    bluetooth_data->localhost_name               = localhost_name;
    bluetooth_data->hci_vendors                  = hci_vendors;

    if (have_tap_listener(bluetooth_tap)) {
        bluetooth_tap_data_t  *bluetooth_tap_data;

        bluetooth_tap_data                = wmem_new(wmem_packet_scope(), bluetooth_tap_data_t);
        bluetooth_tap_data->interface_id  = bluetooth_data->interface_id;
        bluetooth_tap_data->adapter_id    = bluetooth_data->adapter_id;

        tap_queue_packet(bluetooth_tap, pinfo, bluetooth_tap_data);
    }

    src = (address *) p_get_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_SRC);
    dst = (address *) p_get_proto_data(wmem_file_scope(), pinfo, proto_bluetooth, BLUETOOTH_DATA_DST);

    if (src && src->type == AT_STRINGZ) {
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_addr_str, tvb, 0, 0, (const char *) src->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_src_str, tvb, 0, 0, (const char *) src->data);
        proto_item_set_generated(sub_item);
    } else if (src && src->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const guint8 *) src->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_src, tvb, 0, 0, (const guint8 *) src->data);
        proto_item_set_generated(sub_item);
    }

    if (dst && dst->type == AT_STRINGZ) {
        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_addr_str, tvb, 0, 0, (const char *) dst->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_string(main_tree, hf_bluetooth_dst_str, tvb, 0, 0, (const char *) dst->data);
        proto_item_set_generated(sub_item);
    } else if (dst && dst->type == AT_ETHER) {
        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_addr, tvb, 0, 0, (const guint8 *) dst->data);
        proto_item_set_hidden(sub_item);

        sub_item = proto_tree_add_ether(main_tree, hf_bluetooth_dst, tvb, 0, 0, (const guint8 *) dst->data);
        proto_item_set_generated(sub_item);
    }

    return bluetooth_data;
}

/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_H4, WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR,
 * WTAP_ENCAP_PACKETLOGGER. WTAP_ENCAP_BLUETOOTH_LE_LL,
 * WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, and WTAP_ENCAP_BLUETOOTH_BREDR_BB.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static gint
dissect_bluetooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * There is no pseudo-header, or there's just a p2p pseudo-header.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_NONE;
    bluetooth_data->previous_protocol_data.none = NULL;

    if (!dissector_try_uint_new(bluetooth_table, pinfo->rec->rec_header.packet_header.pkt_encap, tvb, pinfo, tree, TRUE, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}


/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_HCI.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static gint
dissect_bluetooth_bthci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a struct bthci_phdr.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_BTHCI;
    bluetooth_data->previous_protocol_data.bthci = (struct bthci_phdr *)data;

    if (!dissector_try_uint_new(bluetooth_table, pinfo->rec->rec_header.packet_header.pkt_encap, tvb, pinfo, tree, TRUE, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/*
 * Register this in the wtap_encap dissector table.
 * It's called for WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR.
 *
 * It does work common to all Bluetooth encapsulations, and then calls
 * the dissector registered in the bluetooth.encap table to handle the
 * metadata header in the packet.
 */
static gint
dissect_bluetooth_btmon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a struct btmon_phdr.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_BTMON;
    bluetooth_data->previous_protocol_data.btmon = (struct btmon_phdr *)data;

    if (!dissector_try_uint_new(bluetooth_table, pinfo->rec->rec_header.packet_header.pkt_encap, tvb, pinfo, tree, TRUE, bluetooth_data)) {
        call_data_dissector(tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

/*
 * Register this in various USB dissector tables.
 */
static gint
dissect_bluetooth_usb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a usb_conv_info_t.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_USB_CONV_INFO;
    bluetooth_data->previous_protocol_data.usb_conv_info = (usb_conv_info_t *)data;

    return call_dissector_with_data(hci_usb_handle, tvb, pinfo, tree, bluetooth_data);
}

/*
 * Register this by name; it's called from the Ubertooth dissector.
 */
static gint
dissect_bluetooth_ubertooth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    bluetooth_data_t  *bluetooth_data;

    bluetooth_data = dissect_bluetooth_common(tvb, pinfo, tree);

    /*
     * data points to a ubertooth_data_t.
     */
    bluetooth_data->previous_protocol_data_type = BT_PD_UBERTOOTH_DATA;
    bluetooth_data->previous_protocol_data.ubertooth_data = (ubertooth_data_t *)data;

    call_dissector(btle_handle, tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void
proto_register_bluetooth(void)
{
    static hf_register_info hf[] = {
        { &hf_bluetooth_src,
            { "Source",                              "bluetooth.src",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_dst,
            { "Destination",                         "bluetooth.dst",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_addr,
            { "Source or Destination",               "bluetooth.addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_src_str,
            { "Source",                              "bluetooth.src_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_dst_str,
            { "Destination",                         "bluetooth.dst_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bluetooth_addr_str,
            { "Source or Destination",               "bluetooth.addr_str",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static hf_register_info oui_hf[] = {
        { &hf_llc_bluetooth_pid,
            { "PID",    "llc.bluetooth_pid",
            FT_UINT16, BASE_HEX, VALS(bluetooth_pid_vals), 0x0,
            "Protocol ID", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_bluetooth,
    };

    /* Decode As handling */
    static build_valid_func bluetooth_uuid_da_build_value[1] = {bluetooth_uuid_value};
    static decode_as_value_t bluetooth_uuid_da_values = {bluetooth_uuid_prompt, 1, bluetooth_uuid_da_build_value};
    static decode_as_t bluetooth_uuid_da = {"bluetooth", "bluetooth.uuid", 1, 0, &bluetooth_uuid_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};


    proto_bluetooth = proto_register_protocol("Bluetooth", "Bluetooth", "bluetooth");
    prefs_register_protocol(proto_bluetooth, NULL);

    register_dissector("bluetooth_ubertooth", dissect_bluetooth_ubertooth, proto_bluetooth);

    proto_register_field_array(proto_bluetooth, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    bluetooth_table = register_dissector_table("bluetooth.encap",
            "Bluetooth Encapsulation", proto_bluetooth, FT_UINT32, BASE_HEX);

    chandle_sessions         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_bdaddr        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    chandle_to_mode          = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    shandle_to_chandle       = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    bdaddr_to_role           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_bdaddr         = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    localhost_name           = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    hci_vendors              = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    hci_vendor_table = register_dissector_table("bluetooth.vendor", "HCI Vendor", proto_bluetooth, FT_UINT16, BASE_HEX);
    bluetooth_uuids          = wmem_tree_new(wmem_epan_scope());

    bluetooth_tap = register_tap("bluetooth");
    bluetooth_device_tap = register_tap("bluetooth.device");
    bluetooth_hci_summary_tap = register_tap("bluetooth.hci_summary");

    bluetooth_uuid_table = register_dissector_table("bluetooth.uuid", "BT Service UUID", proto_bluetooth, FT_STRING, BASE_NONE);
    llc_add_oui(OUI_BLUETOOTH, "llc.bluetooth_pid", "LLC Bluetooth OUI PID", oui_hf, proto_bluetooth);

    register_conversation_table(proto_bluetooth, TRUE, bluetooth_conversation_packet, bluetooth_hostlist_packet);

    register_decode_as(&bluetooth_uuid_da);
}

void
proto_reg_handoff_bluetooth(void)
{
    dissector_handle_t bluetooth_handle = create_dissector_handle(dissect_bluetooth, proto_bluetooth);
    dissector_handle_t bluetooth_bthci_handle = create_dissector_handle(dissect_bluetooth_bthci, proto_bluetooth);
    dissector_handle_t bluetooth_btmon_handle = create_dissector_handle(dissect_bluetooth_btmon, proto_bluetooth);
    dissector_handle_t bluetooth_usb_handle = create_dissector_handle(dissect_bluetooth_usb, proto_bluetooth);
    dissector_handle_t eapol_handle;
    dissector_handle_t btl2cap_handle;

    btle_handle = find_dissector_add_dependency("btle", proto_bluetooth);
    hci_usb_handle = find_dissector_add_dependency("hci_usb", proto_bluetooth);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_HCI,           bluetooth_bthci_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4,            bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR,  bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LINUX_MONITOR, bluetooth_btmon_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_PACKETLOGGER,            bluetooth_handle);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL,           bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_LE_LL_WITH_PHDR, bluetooth_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_BREDR_BB,        bluetooth_handle);

    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x1131 << 16) | 0x1001, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x050d << 16) | 0x0081, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x2198, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x0a5c << 16) | 0x21e8, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x04bf << 16) | 0x0320, bluetooth_usb_handle);
    dissector_add_uint("usb.product", (0x13d3 << 16) | 0x3375, bluetooth_usb_handle);

    dissector_add_uint("usb.protocol", 0xE00101, bluetooth_usb_handle);
    dissector_add_uint("usb.protocol", 0xE00104, bluetooth_usb_handle);

    dissector_add_for_decode_as("usb.device", bluetooth_usb_handle);

    wmem_tree_insert_string(bluetooth_uuids, "00000001-0000-1000-8000-0002EE000002", "SyncML Server", 0);
    wmem_tree_insert_string(bluetooth_uuids, "00000002-0000-1000-8000-0002EE000002", "SyncML Client", 0);
    wmem_tree_insert_string(bluetooth_uuids, "7905F431-B5CE-4E99-A40F-4B1E122D00D0", "Apple Notification Center Service", 0);

    eapol_handle = find_dissector("eapol");
    btl2cap_handle = find_dissector("btl2cap");

    dissector_add_uint("llc.bluetooth_pid", AMP_C_SECURITY_FRAME, eapol_handle);
    dissector_add_uint("llc.bluetooth_pid", AMP_U_L2CAP, btl2cap_handle);

/* TODO: Add UUID128 verion of UUID16; UUID32? UUID16? */
}

static int proto_btad_apple_ibeacon = -1;

static int hf_btad_apple_ibeacon_uuid128 = -1;
static int hf_btad_apple_ibeacon_major = -1;
static int hf_btad_apple_ibeacon_minor = -1;

static gint ett_btad_apple_ibeacon = -1;

static dissector_handle_t btad_apple_ibeacon;

void proto_register_btad_apple_ibeacon(void);
void proto_reg_handoff_btad_apple_ibeacon(void);


static gint
dissect_btad_apple_ibeacon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree       *main_tree;
    proto_item       *main_item;
    gint              offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_apple_ibeacon, tvb, offset, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btad_apple_ibeacon);

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_uuid128, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_major, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(main_tree, hf_btad_apple_ibeacon_minor, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

void
proto_register_btad_apple_ibeacon(void)
{
    static hf_register_info hf[] = {
        {&hf_btad_apple_ibeacon_uuid128,
            {"UUID",                             "bluetooth.apple.ibeacon.uuid128",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btad_apple_ibeacon_major,
          { "Major",                             "bluetooth.apple.ibeacon.major",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_apple_ibeacon_minor,
          { "Minor",                             "bluetooth.apple.ibeacon.minor",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btad_apple_ibeacon,
    };

    proto_btad_apple_ibeacon = proto_register_protocol("Apple iBeacon", "iBeacon", "ibeacon");
    proto_register_field_array(proto_btad_apple_ibeacon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_apple_ibeacon = register_dissector("bluetooth.apple.ibeacon", dissect_btad_apple_ibeacon, proto_btad_apple_ibeacon);
}


void
proto_reg_handoff_btad_apple_ibeacon(void)
{
    dissector_add_for_decode_as("btcommon.eir_ad.manufacturer_company_id", btad_apple_ibeacon);
}


static int proto_btad_alt_beacon = -1;

static int hf_btad_alt_beacon_code = -1;
static int hf_btad_alt_beacon_id = -1;
static int hf_btad_alt_beacon_reference_rssi = -1;
static int hf_btad_alt_beacon_manufacturer_data = -1;

static gint ett_btad_alt_beacon = -1;

static dissector_handle_t btad_alt_beacon;

void proto_register_btad_alt_beacon(void);
void proto_reg_handoff_btad_alt_beacon(void);


static gint
dissect_btad_alt_beacon(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree       *main_tree;
    proto_item       *main_item;
    gint              offset = 0;

    main_item = proto_tree_add_item(tree, proto_btad_alt_beacon, tvb, offset, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btad_alt_beacon);

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_id, tvb, offset, 20, ENC_NA /* ENC_BIG_ENDIAN */);
    offset += 20;

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_reference_rssi, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(main_tree, hf_btad_alt_beacon_manufacturer_data, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}

void
proto_register_btad_alt_beacon(void)
{
    static hf_register_info hf[] = {
        { &hf_btad_alt_beacon_code,
          { "Code",                              "bluetooth.alt_beacon.code",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_btad_alt_beacon_id,
            {"ID",                               "bluetooth.alt_beacon.id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_btad_alt_beacon_reference_rssi,
          { "Reference RSSI",                    "bluetooth.alt_beacon.reference_rssi",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btad_alt_beacon_manufacturer_data,
          { "Manufacturer Data",                 "bluetooth.alt_beacon.manufacturer_data",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_btad_alt_beacon,
    };

    proto_btad_alt_beacon = proto_register_protocol("AltBeacon", "AltBeacon", "alt_beacon");
    proto_register_field_array(proto_btad_alt_beacon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_alt_beacon = register_dissector("bluetooth.alt_beacon", dissect_btad_alt_beacon, proto_btad_alt_beacon);
}

void
proto_reg_handoff_btad_alt_beacon(void)
{
    dissector_add_for_decode_as("btcommon.eir_ad.manufacturer_company_id", btad_alt_beacon);
}

static int proto_btad_gaen = -1;

static int hf_btad_gaen_rpi128 = -1;
static int hf_btad_gaen_aemd32 = -1;

static gint ett_btad_gaen = -1;

static dissector_handle_t btad_gaen;

void proto_register_btad_gaen(void);
void proto_reg_handoff_btad_gaen(void);

static gint
dissect_btad_gaen(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree       *main_tree;
    proto_item       *main_item;
    gint             offset = 0;

    /* The "Service Data" blob of data has the following format for GAEN:
    1 byte: length (0x17)
    1 byte: Type (0x16)
    2 bytes: Identifier (should be 0xFD6F again)
    16 bytes: Rolling Proximity Identifier
    4 bytes: Associated Encrypted Metadata (Encrypted in AES-CTR mode)
    1 byte: Version
    1 byte: Power level
    2 bytes: Reserved for future use.

    We want to skip everything before the last 20 bytes, because it'll be handled by other parts of the BTLE dissector. */
    offset = tvb_captured_length(tvb) - 20;

    main_item = proto_tree_add_item(tree, proto_btad_gaen, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_btad_gaen);

    proto_tree_add_item(main_tree, hf_btad_gaen_rpi128, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(main_tree, hf_btad_gaen_aemd32, tvb, offset, 4, ENC_NA);
    offset += 4;

    return offset;
}

void
proto_register_btad_gaen(void)
{
    static hf_register_info hf[] = {
        { &hf_btad_gaen_rpi128,
    { "Rolling Proximity Identifier",    "bluetooth.gaen.rpi",
    FT_BYTES, BASE_NONE, NULL, 0x0,
    NULL, HFILL }
        },
    { &hf_btad_gaen_aemd32,
    { "Associated Encrypted Metadata",   "bluetooth.gaen.aemd",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    }
    };

    static gint *ett[] = {
        &ett_btad_gaen,
    };

    proto_btad_gaen = proto_register_protocol("Google/Apple Exposure Notification", "Google/Apple Exposure Notification", "bluetooth.gaen");
    proto_register_field_array(proto_btad_gaen, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    btad_gaen = register_dissector("bluetooth.gaen", dissect_btad_gaen, proto_btad_gaen);
}

void
proto_reg_handoff_btad_gaen(void)
{
    dissector_add_for_decode_as("btcommon.eir_ad.manufacturer_company_id", btad_gaen);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */