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

#include <wx/socket.h>

#include "GatewayProtocolHandler.h"
#include "CCITTChecksumReverse.h"
#include "DStarDefines.h"
#include "Utils.h"

// #define	DUMP_TX

const unsigned int BUFFER_LENGTH = 255U;

CGatewayProtocolHandler::CGatewayProtocolHandler(const wxIPV4address &localAddress) :
m_socket(localAddress),
m_type(NETWORK_NONE),
m_buffer(NULL),
m_length(0U)
{
	m_buffer = new unsigned char[BUFFER_LENGTH];

	::srand(wxDateTime::UNow().GetMillisecond());
}

CGatewayProtocolHandler::~CGatewayProtocolHandler()
{
	delete[] m_buffer;
}

bool CGatewayProtocolHandler::writeHeader(const unsigned char* header, wxUint16 id, const wxIPV4address &address)
{
	unsigned char buffer[50U];

	buffer[0] = 'D';
	buffer[1] = 'S';
	buffer[2] = 'R';
	buffer[3] = 'P';

	buffer[4] = 0x20U;

	buffer[5] = id / 256U;	// Unique session id
	buffer[6] = id % 256U;

	buffer[7] = 0U;

	::memcpy(buffer + 8U, header + 0U, RADIO_HEADER_LENGTH_BYTES - 2U);

	// Get the checksum for the header
	CCCITTChecksumReverse csum;
	csum.update(buffer + 8U, RADIO_HEADER_LENGTH_BYTES - 2U);
	csum.result(buffer + 8U + RADIO_HEADER_LENGTH_BYTES - 2U);

#if defined(DUMP_TX)
	CUtils::dump(wxT("Sending Header"), buffer, 49U);
#endif

	for (unsigned int i = 0U; i < 4U; i++) {
		m_socket.SendTo(address, buffer, 49);
		if(m_socket.Error())
			return false;
	}

	return true;
}

bool CGatewayProtocolHandler::writeData(const unsigned char* data, unsigned int length, wxUint16 id, wxUint8 seqNo, const wxIPV4address &address)
{
	wxASSERT(data != NULL);
	wxASSERT(length == DV_FRAME_LENGTH_BYTES || length == DV_FRAME_MAX_LENGTH_BYTES);

	unsigned char buffer[30U];

	buffer[0] = 'D';
	buffer[1] = 'S';
	buffer[2] = 'R';
	buffer[3] = 'P';

	buffer[4] = 0x21U;

	buffer[5] = id / 256U;	// Unique session id
	buffer[6] = id % 256U;

	buffer[7] = seqNo;

	buffer[8] = 0U;

	::memcpy(buffer + 9U, data, length);

#if defined(DUMP_TX)
	CUtils::dump(wxT("Sending Data"), buffer, length + 9U);
#endif

	m_socket.SendTo(address, buffer, length + 9);
	return m_socket.Error();
}

NETWORK_TYPE CGatewayProtocolHandler::read(wxUint16& id, wxIPV4address &address)
{
	bool res = true;

	// Loop until we have no more data from the socket or we have data for the higher layers
	while (res)
		res = readPackets(id, address);

	return m_type;
}

bool CGatewayProtocolHandler::readPackets(wxUint16& id, wxIPV4address &address)
{
	m_type = NETWORK_NONE;

	m_socket.RecvFrom(address, m_buffer, BUFFER_LENGTH);
	m_length = m_socket.LastReadCount();
	if (m_length <= 0)
		return false;

	// Invalid packet type?
	if (m_buffer[0] == 'D' && m_buffer[1] == 'S' && m_buffer[2] == 'R' && m_buffer[3] == 'P') {
		// Header data
		if (m_buffer[4] == 0x20U) {
			id = m_buffer[5U] * 256U + m_buffer[6U];
			m_type = NETWORK_HEADER;
			return false;
		}

		// User data
		else if (m_buffer[4] == 0x21U) {
			id = m_buffer[5U] * 256U + m_buffer[6U];
			m_type = NETWORK_DATA;
			return false;
		}

		// Register data
		else if (m_buffer[4] == 0x0BU) {
			m_type = NETWORK_REGISTER;
			return false;
		}
	}

	CUtils::dump(wxT("Unknown packet from the Repeater"), m_buffer, m_length);

	return true;
}

unsigned int CGatewayProtocolHandler::readHeader(unsigned char* buffer, unsigned int length)
{
	if (m_type != NETWORK_HEADER)
		return 0U;

	// If the checksum is 0xFFFF then we accept the header without testing the checksum
	if (m_buffer[47U] == 0xFFU && m_buffer[48U] == 0xFFU) {
		::memcpy(buffer, m_buffer + 8U, RADIO_HEADER_LENGTH_BYTES);
		return RADIO_HEADER_LENGTH_BYTES;
	}

	// Get the checksum for the header
	CCCITTChecksumReverse csum;
	csum.update(m_buffer + 8U, RADIO_HEADER_LENGTH_BYTES - 2U);

	bool check = csum.check(m_buffer + 8U + RADIO_HEADER_LENGTH_BYTES - 2U);
	if (!check) {
		CUtils::dump(wxT("Header checksum failure from the Repeater"), m_buffer + 8U, RADIO_HEADER_LENGTH_BYTES);
		return 0U;
	}

	::memcpy(buffer, m_buffer + 8U, RADIO_HEADER_LENGTH_BYTES);

	return RADIO_HEADER_LENGTH_BYTES;
}

unsigned int CGatewayProtocolHandler::readData(unsigned char* buffer, unsigned int length, wxUint8& seqNo, unsigned int& errors)
{
	if (m_type != NETWORK_DATA)
		return 0U;

	unsigned int dataLen = m_length - 9U;

	// Is our buffer too small?
	if (dataLen > length)
		dataLen = length;

	seqNo = m_buffer[7U];

	errors = m_buffer[8U];

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

unsigned int CGatewayProtocolHandler::readRegister(wxString& name)
{
	if (m_type != NETWORK_REGISTER)
		return 0U;

	name = wxString((char*)(m_buffer + 5U), wxConvLocal);

	return m_length - 6U;
}
