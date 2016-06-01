/*
 *   Copyright (C) 2009-2014 by Jonathan Naylor G4KLX
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdexcept>
#include <stdint.h>

#include "RepeaterProtocolHandler.h"
#include "CCITTChecksumReverse.h"
#include "DStarDefines.h"
#include "Utils.h"

// #define	DUMP_TX

const unsigned int BUFFER_LENGTH = 255U;

#pragma pack(push, 1)
struct gatewayPacket {
    char magic[4];
    unsigned char packetType;
    union {
        struct {
            uint16_t streamId;
            uint8_t lastPacket;
            uint8_t flags[3];
            char rpt1Call[8];
            char rpt2Call[8];
            char urCall[8];
            char myCall[8];
            char myCall2[4];
            uint16_t checksum;
        } dstarHeader;
        struct {
            uint16_t streamId;
            uint8_t sequence;
            uint8_t errors;
            uint8_t ambeData[9];
            uint8_t slowData[3];
        } dstarData;
        struct {
            char local[20];
            char status;
            char reflector[8];
        } networkText;
        char pollText[250];
    };
};
#pragma pack(pop)

static const char GW_PACKET_TYPE_HEADER = 0x20;
static const char GW_PACKET_TYPE_DATA = 0x21;
static const char GW_PACKET_TYPE_POLL = 0x0A;

static const char SYNC_SEQUENCE[] = { 0x55, 0x2D, 0x16 };

CRepeaterProtocolHandler::CRepeaterProtocolHandler(const wxIPV4address& localAddress, const wxIPV4address& gatewayAddress, const wxString& name) :
m_socket(localAddress, wxSOCKET_REUSEADDR | wxSOCKET_NOWAIT),
m_gatewayAddress(gatewayAddress),
m_name(name),
m_outId(0U),
m_outSeq(0U),
m_type(NETWORK_NONE),
m_inId(0U),
m_buffer(NULL),
m_length(0U)
{
	m_buffer = new unsigned char[BUFFER_LENGTH];

	::srand(wxDateTime::UNow().GetMillisecond());
}

CRepeaterProtocolHandler::~CRepeaterProtocolHandler()
{
	delete[] m_buffer;
}

bool CRepeaterProtocolHandler::write(const CHeaderData& header, bool busy)
{
	struct gatewayPacket packet = {};

	memcpy(&packet.magic, "DSRP", sizeof(packet.magic));
	packet.packetType = GW_PACKET_TYPE_HEADER;
	if(busy)
		packet.packetType |= 0x02;

	m_outId = (rand() % 65535) + 1;
	packet.dstarHeader.streamId = wxUINT16_SWAP_ON_LE(m_outId);

	//  XXX modify method on the header class to array-ize these
	packet.dstarHeader.flags[0] = header.getFlag1();
	packet.dstarHeader.flags[1] = header.getFlag2();
	packet.dstarHeader.flags[2] = header.getFlag3();

	strncpy(packet.dstarHeader.rpt1Call, header.getRptCall1().c_str(), LONG_CALLSIGN_LENGTH);
	strncpy(packet.dstarHeader.rpt2Call, header.getRptCall2().c_str(), LONG_CALLSIGN_LENGTH);
	strncpy(packet.dstarHeader.urCall, header.getYourCall().c_str(), LONG_CALLSIGN_LENGTH);
	strncpy(packet.dstarHeader.myCall, header.getMyCall1().c_str(), LONG_CALLSIGN_LENGTH);
	strncpy(packet.dstarHeader.myCall2, header.getMyCall2().c_str(), SHORT_CALLSIGN_LENGTH);

	//  XXX The method should probably take void * as the data
	CCCITTChecksumReverse csum;
	csum.update((const unsigned char *) &packet.dstarHeader.flags, 4 * LONG_CALLSIGN_LENGTH + SHORT_CALLSIGN_LENGTH + 3);
	csum.result((unsigned char *) &packet.dstarHeader.checksum);

	m_outSeq = 0;

#if defined(DUMP_TX)
	CUtils::dump(wxS("Sending Header"), (const unsigned char *) &packet, 49);
#endif

	for(int i = 0; i < 2; ++i) {
		m_socket.SendTo(m_gatewayAddress, &packet, 49);
		if(m_socket.Error())
			return false;
	}

	return true;
}

bool CRepeaterProtocolHandler::write(const void* data, unsigned int length, unsigned int errors, bool end, bool busy)
{
	wxASSERT(data != NULL);
	wxASSERT(length == DV_FRAME_LENGTH_BYTES || length == DV_FRAME_MAX_LENGTH_BYTES);

	struct gatewayPacket packet = {};
	const char *slowData = (const char *)data + 9;

	memcpy(&packet.magic, "DSRP", sizeof(packet.magic));
	packet.packetType = GW_PACKET_TYPE_DATA;
	if(busy)
		packet.packetType |= 0x02;

	packet.dstarData.streamId = wxUINT16_SWAP_ON_LE(m_outId);

	if(!memcmp(slowData, SYNC_SEQUENCE, 3))
		m_outSeq = 0;

	packet.dstarData.sequence = m_outSeq;
	if(end)
		packet.dstarData.sequence |= 0x40;

	packet.dstarData.errors = errors;

	if(++m_outSeq > 0x14U)
		m_outSeq = 0;

	memcpy(&packet.dstarData.ambeData, data, length);

#if defined(DUMP_TX)
	CUtils::dump(wxT("Sending Data"), &packet, length + 9);
#endif

	m_socket.SendTo(m_gatewayAddress, &packet, length + 9);
	return m_socket.Error();
}

bool CRepeaterProtocolHandler::writePoll(const wxString& text)
{
	unsigned char buffer[40U];

	buffer[0] = 'D';
	buffer[1] = 'S';
	buffer[2] = 'R';
	buffer[3] = 'P';

	buffer[4] = 0x0A;				// Poll with text

	unsigned int length = text.Length();

	for (unsigned int i = 0U; i < length; i++)
		buffer[5U + i] = text.GetChar(i);

	buffer[5U + length] = 0x00;

#if defined(DUMP_TX)
	CUtils::dump(wxT("Sending Poll"), buffer, 6U + length);
#endif

	m_socket.SendTo(m_gatewayAddress, buffer, length + 6);
	return m_socket.Error();
}

bool CRepeaterProtocolHandler::writeRegister()
{
	unsigned char buffer[40U];

	buffer[0] = 'D';
	buffer[1] = 'S';
	buffer[2] = 'R';
	buffer[3] = 'P';

	buffer[4] = 0x0B;				// Register with name

	unsigned int length = m_name.Length();

	for (unsigned int i = 0U; i < length; i++)
		buffer[5U + i] = m_name.GetChar(i);

	buffer[5U + length] = 0x00;

#if defined(DUMP_TX)
	CUtils::dump(wxT("Sending Register"), buffer, 6U + length);
#endif

	m_socket.SendTo(m_gatewayAddress, buffer, length + 6);
	return m_socket.Error();
}

NETWORK_TYPE CRepeaterProtocolHandler::read()
{
	bool res = true;

	// Loop until we have no more data from the socket or we have data for the higher layers
	while (res)
		res = readPackets();

	return m_type;
}

bool CRepeaterProtocolHandler::readPackets()
{
	m_type = NETWORK_NONE;

	wxIPV4address remoteAddress;
	m_socket.RecvFrom(remoteAddress, m_buffer, BUFFER_LENGTH);
	m_length = m_socket.LastReadCount();

	if (m_length <= 0)
		return false;

	//  XXX This is a little hinky.  wxWidgets doesn't properly overload !=
	if(!(remoteAddress == m_gatewayAddress)) {
		wxLogMessage(wxT("Packet received from an invalid source, %s != %s and/or %u != %u"),
			m_gatewayAddress.IPAddress(), remoteAddress.IPAddress(),
			m_gatewayAddress.Service(), remoteAddress.Service());
		CUtils::dump(wxT("Data"), m_buffer, m_length);
		return false;
	}

	// Invalid packet type?
	if (m_buffer[0] == 'D' && m_buffer[1] == 'S' && m_buffer[2] == 'R' && m_buffer[3] == 'P') {
		if (m_buffer[4] == 0x00U) {
			m_type = NETWORK_TEXT;
			return false;
		}

		if (m_buffer[4] == 0x01U) {
			m_type = NETWORK_TEMPTEXT;
			return false;
		}

		// Status data 1
		else if (m_buffer[4] == 0x04U && m_buffer[5] == 0x00U) {
			m_type = NETWORK_STATUS1;
			return false;
		}

		// Status data 2
		else if (m_buffer[4] == 0x04U && m_buffer[5] == 0x01U) {
			m_type = NETWORK_STATUS2;
			return false;
		}

		// Status data 3
		else if (m_buffer[4] == 0x04U && m_buffer[5] == 0x02U) {
			m_type = NETWORK_STATUS3;
			return false;
		}

		// Status data 4
		else if (m_buffer[4] == 0x04U && m_buffer[5] == 0x03U) {
			m_type = NETWORK_STATUS4;
			return false;
		}

		// Status data 5
		else if (m_buffer[4] == 0x04U && m_buffer[5] == 0x04U) {
			m_type = NETWORK_STATUS5;
			return false;
		}

		// Header data
		else if (m_buffer[4] == 0x20U) {
			wxUint16 id = m_buffer[5] * 256U + m_buffer[6];

			// Are we listening for headers?
			if (m_inId != 0U)
				return true;

			m_inId = id;					// Take the stream id
			m_type = NETWORK_HEADER;
			return false;
		}

		// User data
		else if (m_buffer[4] == 0x21U) {
			wxUint16 id = m_buffer[5] * 256U + m_buffer[6];

			// Check that the stream id matches the valid header, reject otherwise
			if (id != m_inId)
				return true;

			// Is this the last packet in the stream?
			if ((m_buffer[7] & 0x40) == 0x40)
				m_inId = 0U;

			m_type = NETWORK_DATA;
			return false;
		}

		else if (m_buffer[4] == 0x24U) {
			// Silently ignore DD data
		}
	}

	CUtils::dump(wxT("Unknown packet from the Gateway"), m_buffer, m_length);

	return true;
}

CHeaderData* CRepeaterProtocolHandler::readHeader()
{
	if (m_type != NETWORK_HEADER)
		return NULL;

	// If the checksum is 0xFFFF then we accept the header without testing the checksum
	if (m_buffer[47U] == 0xFFU && m_buffer[48U] == 0xFFU)
		return new CHeaderData(m_buffer + 8U, RADIO_HEADER_LENGTH_BYTES, false);

	// Header checksum testing is enabled
	CHeaderData* header = new CHeaderData(m_buffer + 8U, RADIO_HEADER_LENGTH_BYTES, true);

	if (!header->isValid()) {
		CUtils::dump(wxT("Header checksum failure from the Gateway"), m_buffer + 8U, RADIO_HEADER_LENGTH_BYTES);
		delete header;
		return NULL;
	}

	return header;
}

unsigned int CRepeaterProtocolHandler::readData(unsigned char* buffer, unsigned int length, unsigned char& seqNo)
{
	if (m_type != NETWORK_DATA)
		return 0U;

	unsigned int dataLen = m_length - 9U;

	// Is our buffer too small?
	if (dataLen > length)
		dataLen = length;

	seqNo = m_buffer[7U];

	::memcpy(buffer, m_buffer + 9U, dataLen);

	// Simple sanity checks of the incoming sync bits
	if (seqNo == 0U) {
		// Regenerate sync bytes
		buffer[9U]  = DATA_SYNC_BYTES[0U];
		buffer[10U] = DATA_SYNC_BYTES[1U];
		buffer[11U] = DATA_SYNC_BYTES[2U];
	} else if (::memcmp(buffer + 9U, DATA_SYNC_BYTES, DATA_FRAME_LENGTH_BYTES) == 0) {
		// Sync bytes appearing where they shouldn't!
		buffer[9U]  = 0x70U;
		buffer[10U] = 0x4FU;
		buffer[11U] = 0x93U;
	}

	return dataLen;
}

void CRepeaterProtocolHandler::readText(wxString& text, LINK_STATUS& status, wxString& reflector)
{
	if (m_type != NETWORK_TEXT) {
		text = wxT("                    ");
		reflector = wxT("        ");
		status = LS_NONE;
		return;
	}

	text = wxString((char*)(m_buffer + 5U), wxConvLocal, 20U);

	status = LINK_STATUS(m_buffer[25U]);

	reflector = wxString((char*)(m_buffer + 26U), wxConvLocal, 8U);
}

void CRepeaterProtocolHandler::readTempText(wxString& text)
{
	if (m_type != NETWORK_TEMPTEXT) {
		text = wxT("                    ");
		return;
	}

	text = wxString((char*)(m_buffer + 5U), wxConvLocal, 20U);
}

wxString CRepeaterProtocolHandler::readStatus1()
{
	if (m_type != NETWORK_STATUS1)
		return wxEmptyString;

	return wxString((char*)(m_buffer + 6U), wxConvLocal, 20U);
}

wxString CRepeaterProtocolHandler::readStatus2()
{
	if (m_type != NETWORK_STATUS2)
		return wxEmptyString;

	return wxString((char*)(m_buffer + 6U), wxConvLocal, 20U);
}

wxString CRepeaterProtocolHandler::readStatus3()
{
	if (m_type != NETWORK_STATUS3)
		return wxEmptyString;

	return wxString((char*)(m_buffer + 6U), wxConvLocal, 20U);
}

wxString CRepeaterProtocolHandler::readStatus4()
{
	if (m_type != NETWORK_STATUS4)
		return wxEmptyString;

	return wxString((char*)(m_buffer + 6U), wxConvLocal, 20U);
}

wxString CRepeaterProtocolHandler::readStatus5()
{
	if (m_type != NETWORK_STATUS5)
		return wxEmptyString;

	return wxString((char*)(m_buffer + 6U), wxConvLocal, 20U);
}

void CRepeaterProtocolHandler::reset()
{
	m_inId = 0U;
}

bool CRepeaterProtocolHandler::isLocal()
{
	return m_gatewayAddress.IsLocalHost();
}
